import { createHash } from 'node:crypto';
import { moduleMutationOperation } from '../module-mutation-operations.js';

import { encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import { evidenceKeyId } from './cose.js';
import { businessTransitionCoseContext } from './generated.js';
import { businessTransitionCoseContextV2 } from './generated-v2.js';
import { businessTransitionProfiles } from './profiles.generated.js';
import { uuidBytes } from './payload.js';
import {
  isExactSigningSecretReference,
  signingSecretReferenceMaxLength,
} from './secret-reference.js';

/** A purpose-bound, immutable grant. Wildcards and caller-selected purposes are not admitted. */
export interface BusinessSigningGrant {
  readonly profileId: string;
  readonly profileVersion: number;
  readonly profileDigest: Buffer;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
}

/** Public trust only. The versioned secret reference identifies a distinct signing key. */
export interface BusinessSigningTrust {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly signerId: string;
  readonly publicKeySpkiDer: Buffer;
  readonly workloadCredentialId: string;
  readonly workloadCredentialEpoch: bigint;
  readonly keyEpoch: bigint;
  readonly validFromNs: bigint;
  readonly validUntilNs: bigint;
  readonly admissionKind: 'BOOTSTRAP' | 'GOVERNED';
  readonly admissionReference: string;
  readonly admissionDigest: Buffer;
  readonly secretClass: 'SECRET-SIGNING-KEY';
  readonly secretReference: string;
  readonly secretVersion: string;
  readonly grants: readonly BusinessSigningGrant[];
}

export interface BusinessSigningRequest extends BusinessSigningGrant {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly nowNs: bigint;
}

export class BusinessSigningTrustError extends Error {
  constructor() {
    super('Control business signing trust is unavailable');
  }
}

function reject(): never {
  throw new BusinessSigningTrustError();
}
function exact(value: object, keys: readonly string[]): void {
  if (
    value === null ||
    typeof value !== 'object' ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    reject();
}
function text(value: string, max: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.normalize('NFC') !== value ||
    Buffer.byteLength(value) > max ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    reject();
  return value;
}
function u64(value: bigint, minimum = 0n): bigint {
  if (typeof value !== 'bigint' || value < minimum || value > MAX_UINT64) reject();
  return value;
}
function digest(value: Buffer): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== 32) reject();
  return value;
}
function grant(value: BusinessSigningGrant): readonly CborValue[] {
  exact(value, [
    'profileId',
    'profileVersion',
    'profileDigest',
    'actionIntentId',
    'catalogOperationId',
  ]);
  if (
    !Number.isInteger(value.profileVersion) ||
    value.profileVersion < 1 ||
    value.profileVersion > 0xffff_ffff ||
    !/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u.test(value.actionIntentId) ||
    (moduleMutationOperation(value.catalogOperationId) !== undefined &&
      !businessTransitionProfiles.some(
        (profile) =>
          profile.catalogOperationId === value.catalogOperationId &&
          profile.profileId === value.profileId &&
          profile.profileVersion === value.profileVersion &&
          profile.actionIntentId === value.actionIntentId &&
          Buffer.from(profile.profileDigest.slice(7), 'hex').equals(value.profileDigest),
      )) ||
    (!/^(ID|CFG)-OP-[A-Z0-9-]+$/u.test(value.catalogOperationId) &&
      moduleMutationOperation(value.catalogOperationId) === undefined &&
      !['OPS-OP-ADVANCE-SIGNING-KEY-ROTATION', 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION'].includes(
        value.catalogOperationId,
      ))
  )
    reject();
  return [
    text(value.profileId, 160),
    value.profileVersion,
    digest(value.profileDigest),
    value.actionIntentId,
    value.catalogOperationId,
  ];
}
function compareGrants(left: BusinessSigningGrant, right: BusinessSigningGrant): number {
  return (
    Buffer.compare(Buffer.from(left.profileId), Buffer.from(right.profileId)) ||
    left.profileVersion - right.profileVersion
  );
}

/** The admitted lifecycle profiles bind v2; an existing v1 key cannot mix in v2 grants. */
export function businessSigningSchemaVersion(trust: Pick<BusinessSigningTrust, 'grants'>): 1 | 2 {
  const lifecycle = trust.grants.some(
    (g) =>
      g.catalogOperationId.startsWith('OPS-OP-') ||
      g.profileId.startsWith('pc.control.signing-rotation.'),
  );
  if (!lifecycle) return 1;
  if (
    trust.grants.length === 0 ||
    trust.grants.some(
      (g) =>
        !businessTransitionProfiles.some(
          (p) =>
            p.schemaDefinitionDigest === businessTransitionCoseContextV2.definitionDigest &&
            p.profileId === g.profileId &&
            p.profileVersion === g.profileVersion &&
            p.actionIntentId === g.actionIntentId &&
            p.catalogOperationId === g.catalogOperationId &&
            Buffer.from(p.profileDigest.slice(7), 'hex').equals(g.profileDigest),
        ),
    )
  )
    reject();
  return 2;
}

/** Hash of the actual fenced public trust tuple, never a claim that the key is currently usable. */
export function businessSigningTrustPreimage(trust: BusinessSigningTrust): Buffer {
  exact(trust, [
    'participantId',
    'privacyDomainId',
    'environmentId',
    'signerId',
    'publicKeySpkiDer',
    'workloadCredentialId',
    'workloadCredentialEpoch',
    'keyEpoch',
    'validFromNs',
    'validUntilNs',
    'admissionKind',
    'admissionReference',
    'admissionDigest',
    'secretClass',
    'secretReference',
    'secretVersion',
    'grants',
  ]);
  if (
    evidenceKeyId(trust.publicKeySpkiDer) !== trust.signerId ||
    !['BOOTSTRAP', 'GOVERNED'].includes(trust.admissionKind) ||
    !Array.isArray(trust.grants) ||
    trust.grants.length < 1 ||
    trust.grants.length > 64 ||
    trust.secretClass !== 'SECRET-SIGNING-KEY' ||
    !isExactSigningSecretReference(trust.secretReference, trust.secretVersion) ||
    trust.validFromNs % 1000n !== 0n ||
    trust.validUntilNs % 1000n !== 0n ||
    trust.validUntilNs <= trust.validFromNs
  )
    reject();
  for (let i = 1; i < trust.grants.length; i++)
    if (compareGrants(trust.grants[i - 1]!, trust.grants[i]!) >= 0) reject();
  return encodeCbor([
    'pc.control.business-signing-trust.v1',
    uuidBytes(trust.participantId),
    uuidBytes(trust.privacyDomainId),
    text(trust.environmentId, 160),
    trust.signerId,
    trust.publicKeySpkiDer,
    uuidBytes(trust.workloadCredentialId),
    u64(trust.workloadCredentialEpoch),
    u64(trust.keyEpoch, 1n),
    u64(trust.validFromNs),
    u64(trust.validUntilNs, 1n),
    trust.admissionKind,
    text(trust.admissionReference, 256),
    digest(trust.admissionDigest),
    trust.secretClass,
    text(trust.secretReference, signingSecretReferenceMaxLength),
    trust.secretVersion,
    businessTransitionCoseContext.schemaId,
    businessSigningSchemaVersion(trust),
    businessTransitionCoseContext.purposeCode,
    trust.grants.map(grant),
  ]);
}

export function businessSigningTrustDigest(trust: BusinessSigningTrust): Buffer {
  return createHash('sha256').update(businessSigningTrustPreimage(trust)).digest();
}

/** The store owner must first lock/revalidate selection, key lifecycle and workload authority. */
export function assertBusinessSigningGrant(
  trust: BusinessSigningTrust,
  request: BusinessSigningRequest,
): void {
  businessSigningTrustPreimage(trust);
  const { participantId, privacyDomainId, environmentId, nowNs, ...requestedGrant } = request;
  grant(requestedGrant);
  u64(nowNs);
  if (
    participantId !== trust.participantId ||
    privacyDomainId !== trust.privacyDomainId ||
    environmentId !== trust.environmentId ||
    nowNs < trust.validFromNs ||
    nowNs >= trust.validUntilNs ||
    !trust.grants.some(
      (item) =>
        item.profileId === request.profileId &&
        item.profileVersion === request.profileVersion &&
        item.profileDigest.equals(request.profileDigest) &&
        item.actionIntentId === request.actionIntentId &&
        item.catalogOperationId === request.catalogOperationId,
    )
  )
    reject();
}
