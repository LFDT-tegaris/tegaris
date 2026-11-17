import { createHash } from 'node:crypto';
import { encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { isExactSigningSecretReference } from '../business-transition/secret-reference.js';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from './generated.js';
import { decodeIdentityAuthorityEnvelope } from './codec.js';
import type { BusinessSigningTrust } from '../business-transition/signing-trust.js';

/** Unsigned, generated admission metadata. Neither an envelope nor a receipt. */
export {
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningProfileDigest,
} from './generated.js';

/** Public immutable key trust in the existing signing key/lifecycle owner.
 * Explicit 371 purpose and profile are required; no receipt grant is inherited. */
export interface IdentityEnvelopeSigningTrust extends Omit<BusinessSigningTrust, 'grants'> {
  readonly workloadParticipantEpoch: bigint;
  readonly workloadPrincipalEpoch: bigint;
  readonly purpose: 'pc.cose.identity-authority-envelope.v1';
  readonly profileId: 'pc.identity.authority-envelope.v1';
  readonly profileVersion: 1;
  readonly profileDigest: string;
}
const reject = (): never => {
  throw new Error('Identity envelope signing trust unavailable');
};
function uuid(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
  )
    return reject();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function text(value: unknown, max: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value) > max ||
    value.normalize('NFC') !== value ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    return reject();
  return value;
}
function number(value: unknown, min = 0n): bigint {
  if (typeof value !== 'bigint' || value < min || value > MAX_UINT64) return reject();
  return value;
}
export function identityEnvelopeSigningTrustPreimage(trust: IdentityEnvelopeSigningTrust): Buffer {
  const keys = [
    'participantId',
    'privacyDomainId',
    'environmentId',
    'signerId',
    'publicKeySpkiDer',
    'workloadCredentialId',
    'workloadCredentialEpoch',
    'workloadParticipantEpoch',
    'workloadPrincipalEpoch',
    'keyEpoch',
    'validFromNs',
    'validUntilNs',
    'admissionKind',
    'admissionReference',
    'admissionDigest',
    'secretClass',
    'secretReference',
    'secretVersion',
    'purpose',
    'profileId',
    'profileVersion',
    'profileDigest',
  ];
  if (
    trust === null ||
    typeof trust !== 'object' ||
    Object.getPrototypeOf(trust) !== Object.prototype ||
    Reflect.ownKeys(trust).length !== keys.length ||
    keys.some(
      (key) =>
        !Object.hasOwn(trust, key) || !('value' in Object.getOwnPropertyDescriptor(trust, key)!),
    )
  )
    return reject();
  if (
    trust.purpose !== identityEnvelopeContext.purpose ||
    trust.profileId !== identityEnvelopeSigningProfile.profileId ||
    trust.profileVersion !== 1 ||
    trust.profileDigest !== identityEnvelopeSigningProfileDigest ||
    trust.signerId !== evidenceKeyId(trust.publicKeySpkiDer) ||
    trust.secretClass !== 'SECRET-SIGNING-KEY' ||
    !isExactSigningSecretReference(trust.secretReference, trust.secretVersion) ||
    !['BOOTSTRAP', 'GOVERNED'].includes(trust.admissionKind) ||
    !Buffer.isBuffer(trust.admissionDigest) ||
    trust.admissionDigest.length !== 32 ||
    number(trust.validUntilNs) <= number(trust.validFromNs) ||
    trust.validFromNs % 1000n !== 0n ||
    trust.validUntilNs % 1000n !== 0n
  )
    return reject();
  const values: CborValue[] = [
    'pc.identity.authority-envelope-signing-trust.v1',
    uuid(trust.participantId),
    uuid(trust.privacyDomainId),
    text(trust.environmentId, 160),
    trust.signerId,
    trust.publicKeySpkiDer,
    uuid(trust.workloadCredentialId),
    number(trust.workloadCredentialEpoch),
    number(trust.workloadParticipantEpoch),
    number(trust.workloadPrincipalEpoch),
    number(trust.keyEpoch, 1n),
    trust.validFromNs,
    trust.validUntilNs,
    trust.admissionKind,
    text(trust.admissionReference, 256),
    trust.admissionDigest,
    trust.secretClass,
    text(trust.secretReference, 331),
    text(trust.secretVersion, 96),
    identityEnvelopeContext.schemaId,
    identityEnvelopeContext.schemaVersion,
    identityEnvelopeContext.purposeCode,
    Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
    [
      trust.profileId,
      trust.profileVersion,
      Buffer.from(trust.profileDigest.slice(7), 'hex'),
      identityEnvelopeSigningProfile.actionIntentId,
      identityEnvelopeSigningProfile.catalogOperationId,
    ],
  ];
  return encodeCbor(values);
}
export function identityEnvelopeSigningTrustDigest(trust: IdentityEnvelopeSigningTrust): string {
  return `sha256:${createHash('sha256').update(identityEnvelopeSigningTrustPreimage(trust)).digest('hex')}`;
}
/** Called under the durable current key/profile/issuer fences. Pure binding
 * validation cannot establish those fences and never performs provider I/O. */
export function assertIdentityEnvelopeSigningTrust(
  payload: Buffer,
  trust: IdentityEnvelopeSigningTrust,
  nowNs: bigint,
): void {
  const trustDigest = identityEnvelopeSigningTrustDigest(trust);
  const artifact = decodeIdentityAuthorityEnvelope(payload);
  const signer = artifact.signer;
  if (
    signer.trustContextDigest !== trustDigest ||
    signer.participantId !== trust.participantId ||
    signer.privacyDomainId !== trust.privacyDomainId ||
    signer.environmentId !== trust.environmentId ||
    signer.profileId !== trust.profileId ||
    signer.profileVersion !== '1' ||
    signer.profileDigest !== trust.profileDigest ||
    signer.keyId !== trust.signerId ||
    signer.keyVersion !== trust.secretVersion ||
    signer.workloadCredentialId !== trust.workloadCredentialId ||
    BigInt(signer.workloadCredentialEpoch) !== trust.workloadCredentialEpoch ||
    number(nowNs) < trust.validFromNs ||
    nowNs >= trust.validUntilNs ||
    BigInt(artifact.issuedAtNs) < trust.validFromNs ||
    BigInt(artifact.issuedAtNs) > nowNs
  )
    return reject();
}
