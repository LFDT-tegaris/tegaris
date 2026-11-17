import { createHash, createPublicKey } from 'node:crypto';
import { encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { isExactSigningSecretReference } from '../business-transition/secret-reference.js';
import { decodeWorkloadRenewalPolicyAuthorization } from './codec.js';
import {
  workloadRenewalSigningProfile,
  workloadRenewalSigningProfileDigest,
} from './generated-signing.js';

export {
  workloadRenewalSigningProfile,
  workloadRenewalSigningProfileDigest,
  workloadRenewalSigningProfileCanonicalJson,
} from './generated-signing.js';

/** Stable public signer trust. The initial key transport credential is retained
 * by its descriptor as provenance but is deliberately absent from this preimage.
 * Actual current transport and permissions are separate mandatory DB owners. */
export interface WorkloadRenewalSigningTrust {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly principalId: string;
  readonly workloadId: string;
  readonly familyId: string;
  readonly familySecurityEpoch: bigint;
  readonly participantSecurityInvalidationEpoch: bigint;
  readonly keySecurityGeneration: bigint;
  readonly signerId: string;
  readonly publicKeySpkiDer: Buffer;
  readonly keyEpoch: bigint;
  readonly validFromNs: bigint;
  readonly validUntilNs: bigint;
  readonly providerQualificationDigest: string;
  readonly admissionKind: 'BOOTSTRAP' | 'GOVERNED';
  readonly admissionReference: string;
  readonly admissionDigest: string;
  readonly secretClass: 'SECRET-SIGNING-KEY';
  readonly secretReference: string;
  readonly secretVersion: string;
  readonly purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1';
  readonly profileId: 'pc.identity.workload-renewal.policy-authorization.v1';
  readonly profileVersion: 2;
  readonly profileDigest: string;
}
export class WorkloadRenewalSigningTrustUnavailable extends Error {
  constructor() {
    super('Workload renewal signing trust is unavailable');
  }
}
const reject = (): never => {
  throw new WorkloadRenewalSigningTrustUnavailable();
};
const hash = (input: unknown) => {
  if (typeof input !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(input)) return reject();
  return Buffer.from(input.slice(7), 'hex');
};
function text(value: unknown, max: number) {
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
function unsigned(value: unknown, min = 0n) {
  if (typeof value !== 'bigint' || value < min || value > MAX_UINT64) return reject();
  return value;
}
function wire(type: string, value: unknown): CborValue {
  switch (type) {
    case 'uuid': {
      if (
        typeof value !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
      )
        return reject();
      return Buffer.from(value.replaceAll('-', ''), 'hex');
    }
    case 'hash':
      return hash(value);
    case 'unsigned':
      return unsigned(value);
    case 'positive':
      return unsigned(value, 1n);
    case 'nanos': {
      const n = unsigned(value);
      if (n % 1000n !== 0n) return reject();
      return n;
    }
    case 'identifier': {
      const id = text(value, 160);
      if (!/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u.test(id)) return reject();
      return id;
    }
    case 'workload': {
      const id = text(value, 128);
      if (!id.startsWith('urn:openpc:workload:')) return reject();
      wire('uuid', id.slice('urn:openpc:workload:'.length));
      return id;
    }
    case 'p256spki': {
      if (!Buffer.isBuffer(value) || value.length !== 91) return reject();
      const key = createPublicKey({ key: value, type: 'spki', format: 'der' });
      if (
        key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !key.export({ type: 'spki', format: 'der' }).equals(value)
      )
        return reject();
      return value;
    }
    case 'admissionKind':
      if (value !== 'BOOTSTRAP' && value !== 'GOVERNED') return reject();
      return value;
    case 'admissionReference':
      return text(value, 256);
    case 'secretClass':
      if (value !== 'SECRET-SIGNING-KEY') return reject();
      return value;
    case 'secretReference':
      return text(value, 331);
    case 'secretVersion':
      return text(value, 96);
    default:
      return reject();
  }
}
/** Generated exact profile/field order, PC-CBOR-1 bytes. Pure provenance binding
 * grants no current signer, provider, permission or instance admission. */
export function workloadRenewalSigningTrustPreimage(trust: WorkloadRenewalSigningTrust): Buffer {
  try {
    const keys = [
      ...workloadRenewalSigningProfile.trustFields.map(([name]) => name),
      'purpose',
      'profileId',
      'profileVersion',
      'profileDigest',
    ];
    if (
      !trust ||
      Object.getPrototypeOf(trust) !== Object.prototype ||
      Reflect.ownKeys(trust).length !== keys.length ||
      keys.some(
        (key) =>
          !Object.hasOwn(trust, key) || !('value' in Object.getOwnPropertyDescriptor(trust, key)!),
      ) ||
      trust.purpose !== workloadRenewalSigningProfile.purpose ||
      trust.profileId !== workloadRenewalSigningProfile.profileId ||
      trust.profileVersion !== 2 ||
      trust.profileDigest !== workloadRenewalSigningProfileDigest ||
      trust.validUntilNs <= trust.validFromNs ||
      !isExactSigningSecretReference(trust.secretReference, trust.secretVersion) ||
      trust.signerId !==
        `sha256:${createHash('sha256').update(trust.publicKeySpkiDer).digest('hex')}`
    )
      return reject();
    const values: CborValue[] = [
      workloadRenewalSigningProfile.trustDomain,
      ...workloadRenewalSigningProfile.trustFields.map(([name, type]) => wire(type, trust[name])),
    ];
    values.push(
      workloadRenewalSigningProfile.schemaId,
      workloadRenewalSigningProfile.schemaVersion,
      workloadRenewalSigningProfile.purposeCode,
      hash(workloadRenewalSigningProfile.schemaDefinitionDigest),
      trust.profileId,
      trust.profileVersion,
      hash(trust.profileDigest),
      workloadRenewalSigningProfile.authorizationMode,
      workloadRenewalSigningProfile.actionIntentId,
      workloadRenewalSigningProfile.catalogOperationId,
    );
    return encodeCbor(values);
  } catch {
    return reject();
  }
}
export function workloadRenewalSigningTrustDigest(trust: WorkloadRenewalSigningTrust) {
  return `sha256:${createHash('sha256').update(workloadRenewalSigningTrustPreimage(trust)).digest('hex')}`;
}
/** Exact artifact binding under an independently authenticated current signer
 * family/credential fence. Neither this tuple nor crypto establishes eligibility. */
export function assertWorkloadRenewalSigningTrust(
  payload: Buffer,
  trust: WorkloadRenewalSigningTrust,
  current: { readonly credentialId: string; readonly credentialEpoch: bigint },
  nowNs: bigint,
) {
  const trustDigest = workloadRenewalSigningTrustDigest(trust),
    artifact = decodeWorkloadRenewalPolicyAuthorization(payload),
    signer = artifact.signer;
  if (
    signer.participantId !== trust.participantId ||
    signer.privacyDomainId !== trust.privacyDomainId ||
    signer.environmentId !== trust.environmentId ||
    signer.workloadId !== trust.workloadId ||
    signer.keyId !== trust.signerId ||
    BigInt(signer.keyEpoch) !== trust.keyEpoch ||
    signer.profileDigest !== trust.profileDigest ||
    signer.trustDigest !== trustDigest ||
    signer.credentialId !== current.credentialId ||
    BigInt(signer.credentialEpoch) !== unsigned(current.credentialEpoch, 1n) ||
    unsigned(nowNs) < trust.validFromNs ||
    nowNs >= trust.validUntilNs ||
    BigInt(artifact.issuedAtNs) < trust.validFromNs ||
    BigInt(artifact.issuedAtNs) > nowNs ||
    BigInt(artifact.validUntilNs) <= nowNs ||
    BigInt(artifact.validUntilNs) > trust.validUntilNs
  )
    return reject();
}
