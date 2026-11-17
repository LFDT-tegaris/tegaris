import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from './canonical-cbor.js';
import {
  encodeIdentityRuntimeActorProjection,
  signIdentityRuntimeProfile,
  verifyIdentityRuntimeProfile,
  type IdentityRuntimeActorProjection,
} from './identity-runtime.js';

const map = (values: readonly CborValue[]) => new Map(values.map((value, key) => [key, value]));
const hash = (value: Buffer) => createHash('sha256').update(value).digest();
function text(value: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value) > 160 ||
    value.normalize('NFC') !== value
  )
    throw new Error('invalid canonical identity identifier');
  return value;
}
function digest(value: Buffer): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error('invalid identity digest');
  return Buffer.from(value);
}
function uint(value: bigint, positive = false): bigint {
  if (typeof value !== 'bigint' || value < (positive ? 1n : 0n) || value > MAX_UINT64)
    throw new Error('invalid identity uint64');
  return value;
}
export function identitySemanticDigest(
  schema: 3001 | 3003 | 3004 | 3005 | 3010,
  payload: Buffer,
): Buffer {
  const envelope = encodeCbor(map([1, schema, 2, decodeCbor(payload)]));
  return hash(Buffer.concat([Buffer.from('pcplane:semantic-digest:v1\0'), envelope]));
}
export interface IdentityAuthorityEntry {
  readonly domainCode: number;
  readonly applicability: 0 | 1;
  readonly scopeDigest: Buffer;
  readonly version: bigint;
}
/** ID-CONTRACT-009 registry scope tuples use canonical CBOR arrays. Unlike
 * schema semantic digests, these tuples have no schema/version envelope. */
export function encodeIdentityAuthorityScope(
  domainCode: number,
  values: readonly (string | Buffer)[],
): { payload: Buffer; digest: Buffer } {
  const lengths = [3, 2, 1, 2, 3, 3, 2, 3, 3, 4, 4, 1];
  if (
    !Number.isInteger(domainCode) ||
    domainCode < 1 ||
    domainCode > 12 ||
    values.length !== lengths[domainCode - 1]
  )
    throw new Error('Invalid authority scope tuple');
  const entries = values.map((value) =>
    domainCode === 12 ? digest(value as Buffer) : text(value as string),
  );
  const payload = encodeCbor(entries);
  return { payload, digest: hash(payload) };
}
/** Canonical tuple digests for one explicit workload runtime context. These
 * bindings are recomputed from the configured target and authenticated peer. */
export function identityRuntimeContextBindings(input: {
  participantId: string;
  privacyDomainId: string;
  targetRuntimeId: string;
}) {
  return {
    participantContextDigest: hash(
      encodeCbor([text(input.participantId), text(input.privacyDomainId)]),
    ),
    targetScopeDigest: hash(
      encodeCbor([
        text(input.participantId),
        text(input.privacyDomainId),
        text(input.targetRuntimeId),
      ]),
    ),
  };
}
export function identityWorkloadRuntimeBindings(input: {
  participantId: string;
  privacyDomainId: string;
  targetRuntimeId: string;
  uriSan: string;
  certificateFingerprint: Buffer;
  publicKeyDigest: Buffer;
}) {
  return {
    ...identityRuntimeContextBindings(input),
    authenticationEvidenceDigest: hash(
      encodeCbor([
        'TLS1.3',
        text(input.uriSan),
        digest(input.certificateFingerprint),
        digest(input.publicKeyDigest),
      ]),
    ),
  };
}
export function identityApplicableDenyScopeSetDigest(scopeIds: readonly string[]): Buffer {
  const scopes = scopeIds.map(text).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (scopes.length === 0 || new Set(scopes).size !== scopes.length)
    throw new Error('Invalid deny scope set');
  return hash(encodeCbor(scopes));
}
export interface IdentityAuthorityVector {
  readonly profileId: string;
  readonly profileVersion: bigint;
  readonly profileSemanticDigest: Buffer;
  readonly entries: readonly IdentityAuthorityEntry[];
}
export function encodeIdentityAuthorityVector(input: IdentityAuthorityVector): Buffer {
  if (input.entries.length !== 12) throw new Error('exactly twelve authority entries required');
  const entries = input.entries.map((entry, index) => {
    const scope = digest(entry.scopeDigest);
    const version = uint(entry.version);
    if (
      entry.domainCode !== index + 1 ||
      (entry.applicability !== 0 && entry.applicability !== 1) ||
      (entry.applicability === 0 && (!scope.equals(Buffer.alloc(32)) || version !== 0n)) ||
      (entry.applicability === 1 && (scope.equals(Buffer.alloc(32)) || version === 0n))
    )
      throw new Error('invalid authority scope or applicability');
    return map([entry.domainCode, entry.applicability, scope, version]);
  });
  return encodeCbor(
    map([
      2,
      text(input.profileId),
      uint(input.profileVersion, true),
      digest(input.profileSemanticDigest),
      entries,
    ]),
  );
}
export interface IdentityRuntimeAuthorityProfile {
  readonly profileId: string;
  readonly profileVersion: bigint;
  readonly applicability: readonly (0 | 1)[];
  readonly highValueActionId?: string;
  readonly profileClass: 1 | 2 | 3;
  readonly signerId: string;
}
export function encodeIdentityRuntimeAuthorityProfile(
  input: IdentityRuntimeAuthorityProfile,
): Buffer {
  if (
    input.applicability.length !== 12 ||
    input.applicability.some((v) => v !== 0 && v !== 1) ||
    input.applicability[11] !== 1 ||
    ![1, 2, 3].includes(input.profileClass)
  )
    throw new Error('invalid identity release profile');
  const fields = new Map<number, CborValue>([
    [0, text(input.profileId)],
    [1, uint(input.profileVersion, true)],
    [2, 2],
    [3, input.applicability],
    [5, input.profileClass],
    [6, text(input.signerId)],
  ]);
  if (input.highValueActionId !== undefined) fields.set(4, text(input.highValueActionId));
  return encodeCbor(fields);
}
export interface IdentitySnapshotActor {
  readonly projection: IdentityRuntimeActorProjection;
  readonly authorityVector: IdentityAuthorityVector;
}
export interface IdentitySnapshotInput {
  readonly snapshotId: string;
  readonly targetScopeDigest: Buffer;
  readonly releaseProfileRegistryDigest: Buffer;
  readonly issuedAtNs: bigint;
  readonly hardExpiryNs: bigint;
  readonly signerId: string;
  readonly actors: readonly IdentitySnapshotActor[];
}
export interface EncodedIdentitySnapshot {
  readonly manifestPayload: Buffer;
  readonly manifestSemanticDigest: Buffer;
  readonly shards: readonly { readonly payload: Buffer; readonly semanticDigest: Buffer }[];
}
/** The producer admits finite complete snapshots; it never truncates actors.
 * Shards contain at most 32 actors, below the canonical per-object byte budget. */
export function encodeIdentityRuntimeSnapshot(
  input: IdentitySnapshotInput,
): EncodedIdentitySnapshot {
  if (
    input.actors.length === 0 ||
    input.actors.length > 8192 ||
    uint(input.issuedAtNs) >= uint(input.hardExpiryNs)
  )
    throw new Error('invalid identity snapshot size or time');
  const actors = [...input.actors].sort((a, b) =>
    Buffer.compare(a.projection.actorKeyDigest, b.projection.actorKeyDigest),
  );
  const states = actors.map((actor, index) => {
    if (
      index > 0 &&
      actor.projection.actorKeyDigest.equals(actors[index - 1]!.projection.actorKeyDigest)
    )
      throw new Error('duplicate snapshot actor');
    const vector = encodeIdentityAuthorityVector(actor.authorityVector);
    if (!identitySemanticDigest(3001, vector).equals(actor.projection.authorityVectorDigest))
      throw new Error('actor authority vector mismatch');
    return map([
      decodeCbor(encodeIdentityRuntimeActorProjection(actor.projection)),
      decodeCbor(vector),
    ]);
  });
  const count = Math.ceil(states.length / 32);
  const shards = Array.from({ length: count }, (_, index) => {
    const entries = states.slice(index * 32, (index + 1) * 32);
    const payload = encodeCbor(
      map([text(input.snapshotId), index, count, entries, hash(encodeCbor(entries))]),
    );
    return { payload, semanticDigest: identitySemanticDigest(3005, payload) };
  });
  const manifestPayload = encodeCbor(
    map([
      text(input.snapshotId),
      digest(input.targetScopeDigest),
      digest(input.releaseProfileRegistryDigest),
      actors.length,
      count,
      shards.map((s) => s.semanticDigest),
      uint(input.issuedAtNs),
      uint(input.hardExpiryNs),
      text(input.signerId),
    ]),
  );
  return {
    manifestPayload,
    manifestSemanticDigest: identitySemanticDigest(3004, manifestPayload),
    shards,
  };
}
function manifestPayload(payload: Buffer): void {
  const fields = decodeCbor(payload);
  if (
    !(fields instanceof Map) ||
    fields.size !== 9 ||
    [...fields.keys()].some((key, index) => key !== index)
  )
    throw new Error('invalid snapshot manifest fields');
  text(fields.get(0) as string);
  digest(fields.get(1) as Buffer);
  digest(fields.get(2) as Buffer);
  text(fields.get(8) as string);
  const actors = uint(fields.get(3) as bigint);
  const count = uint(fields.get(4) as bigint, true);
  const shards = fields.get(5);
  if (
    !Array.isArray(shards) ||
    shards.length === 0 ||
    shards.length > 256 ||
    BigInt(shards.length) !== count ||
    actors < count
  )
    throw new Error('invalid snapshot counts');
  for (const shard of shards) digest(shard as Buffer);
  if (uint(fields.get(6) as bigint) >= uint(fields.get(7) as bigint))
    throw new Error('invalid snapshot time');
}
export function signIdentityRuntimeSnapshotManifestCoseSign1Ed25519(
  privateKey: Buffer,
  publicKey: Buffer,
  payload: Buffer,
): Buffer {
  manifestPayload(payload);
  return signIdentityRuntimeProfile(3004, privateKey, publicKey, payload);
}
export function verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519(
  publicKey: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    manifestPayload(payload);
    return verifyIdentityRuntimeProfile(3004, publicKey, payload, cose);
  } catch {
    return false;
  }
}
export function signIdentityRuntimeAuthorityProfileCoseSign1Ed25519(
  privateKey: Buffer,
  publicKey: Buffer,
  input: IdentityRuntimeAuthorityProfile,
): { payload: Buffer; coseSign1: Buffer; semanticDigest: Buffer } {
  const payload = encodeIdentityRuntimeAuthorityProfile(input);
  return {
    payload,
    coseSign1: signIdentityRuntimeProfile(3010, privateKey, publicKey, payload),
    semanticDigest: identitySemanticDigest(3010, payload),
  };
}
