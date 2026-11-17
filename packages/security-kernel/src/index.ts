import { createHash, createPrivateKey, sign, timingSafeEqual, verify } from 'node:crypto';
import { TextDecoder } from 'node:util';

export * from './identity-envelope/types.js';
export * from './identity-envelope/codec.js';
export * from './identity-envelope/cose.js';
export * from './identity-envelope/signing-trust.js';
export * from './identity-envelope/platform-scope.js';
export * from './identity-envelope/platform-scope-successor.js';
export * from './identity-envelope/platform-scope-expiry-recovery.js';
export { identityEnvelopeContext } from './identity-envelope/generated.js';
export * from './workload-signing-handover/admission-authorization.js';

export {
  decodeIdentityRuntimeActorProjection,
  encodeIdentityRuntimeActorProjection,
  signIdentityRuntimeActorProjectionCoseSign1Ed25519,
  verifyIdentityRuntimeActorProjectionCoseSign1Ed25519,
  type IdentityRuntimeActorProjection,
  decodeIdentityAuthContextAssertionPayload,
  encodeIdentityAuthContextAssertionPayload,
  identityAuthContextAssertionCoseContext,
  signIdentityAuthContextAssertionCoseSign1Ed25519,
  verifyIdentityAuthContextAssertionCoseSign1Ed25519,
  type IdentityAuthContextAssertionPayload,
} from './identity-runtime.js';

interface ByteString {
  readonly bytes: Buffer;
  readonly next: number;
}

interface TextString {
  readonly next: number;
  readonly value: string;
}

export interface CoseProtectedContext {
  readonly purpose: string;
  readonly schemaId: number;
}

export const identityCredentialCoseContext: CoseProtectedContext = {
  purpose: 'openpc:identity-credential:v1',
  schemaId: 22501,
};

const identityCredentialSchemaVersion = '1.0.0';
const identityCredentialSchemaDigest = Buffer.from(
  '2bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b1111',
  'hex',
);
const uuidV7Urn =
  /^urn:openpc:(participant|principal):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uint64Text = /^(0|[1-9][0-9]*)$/u;
const utcMicros = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/u;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export interface IdentityCredentialPayload {
  readonly participantId: string;
  readonly principalId: string;
  readonly authorityEpoch: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

function readLength(input: Buffer, offset: number, expectedMajor: number): [number, number] {
  const initial = input[offset];
  if (initial === undefined || initial >> 5 !== expectedMajor) throw new Error('invalid CBOR type');
  const additional = initial & 0x1f;
  if (additional < 24) return [additional, offset + 1];
  if (additional === 24) {
    const value = input[offset + 1];
    if (value === undefined || value < 24) throw new Error('non-canonical CBOR length');
    return [value, offset + 2];
  }
  if (additional === 25) {
    if (offset + 3 > input.length) throw new Error('truncated CBOR length');
    const value = input.readUInt16BE(offset + 1);
    if (value <= 0xff) throw new Error('non-canonical CBOR length');
    return [value, offset + 3];
  }
  if (additional === 26) {
    if (offset + 5 > input.length) throw new Error('truncated CBOR length');
    const value = input.readUInt32BE(offset + 1);
    if (value <= 0xffff) throw new Error('non-canonical CBOR length');
    return [value, offset + 5];
  }
  throw new Error('unsupported CBOR length');
}

function readByteString(input: Buffer, offset: number): ByteString {
  const [length, start] = readLength(input, offset, 2);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR byte string');
  return { bytes: input.subarray(start, end), next: end };
}

function readTextString(input: Buffer, offset: number): TextString {
  const [length, start] = readLength(input, offset, 3);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR text string');
  const value = utf8Decoder.decode(input.subarray(start, end));
  return { next: end, value };
}

function readInteger(
  input: Buffer,
  offset: number,
): { readonly next: number; readonly value: number } {
  const initial = input[offset];
  if (initial === undefined || (initial >> 5 !== 0 && initial >> 5 !== 1)) {
    throw new Error('CBOR integer required');
  }
  const major = initial >> 5;
  const [magnitude, next] = readLength(input, offset, major);
  return { next, value: major === 0 ? magnitude : -1 - magnitude };
}

function assertCanonicalKeyOrder(previous: Buffer | undefined, current: Buffer): void {
  if (
    previous !== undefined &&
    (previous.length > current.length ||
      (previous.length === current.length && Buffer.compare(previous, current) >= 0))
  ) {
    throw new Error('non-canonical CBOR map order');
  }
}

function readCanonicalIntegerKey(
  input: Buffer,
  offset: number,
  previous: Buffer | undefined,
): { readonly encoded: Buffer; readonly next: number; readonly value: number } {
  const key = readInteger(input, offset);
  const encoded = input.subarray(offset, key.next);
  assertCanonicalKeyOrder(previous, encoded);
  return { encoded, next: key.next, value: key.value };
}

function validateProtectedHeader(
  protectedHeader: Buffer,
  expectedKeyId: Buffer,
  context: CoseProtectedContext,
): void {
  const [entries, start] = readLength(protectedHeader, 0, 5);
  let offset = start;
  let algorithm: number | undefined;
  let contentType: string | undefined;
  let keyId: Buffer | undefined;
  let purpose: string | undefined;
  let schemaId: number | undefined;
  const seen = new Set<number>();
  let previousKey: Buffer | undefined;
  for (let index = 0; index < entries; index += 1) {
    const key = readCanonicalIntegerKey(protectedHeader, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if (seen.has(key.value)) throw new Error('duplicate COSE protected header');
    seen.add(key.value);
    if (key.value === 1) {
      const value = readInteger(protectedHeader, offset);
      algorithm = value.value;
      offset = value.next;
    } else if (key.value === 3) {
      const value = readTextString(protectedHeader, offset);
      contentType = value.value;
      offset = value.next;
    } else if (key.value === 4) {
      const value = readByteString(protectedHeader, offset);
      keyId = value.bytes;
      offset = value.next;
    } else if (key.value === 1001) {
      const value = readInteger(protectedHeader, offset);
      schemaId = value.value;
      offset = value.next;
    } else if (key.value === 1002) {
      const value = readTextString(protectedHeader, offset);
      purpose = value.value;
      offset = value.next;
    } else {
      throw new Error('unknown COSE protected header');
    }
  }
  if (
    entries !== 5 ||
    offset !== protectedHeader.length ||
    algorithm !== -7 ||
    contentType !== 'application/openpc+cbor' ||
    keyId === undefined ||
    keyId.length !== expectedKeyId.length ||
    !timingSafeEqual(keyId, expectedKeyId) ||
    schemaId !== context.schemaId ||
    purpose !== context.purpose
  ) {
    throw new Error('COSE protected header context is invalid');
  }
}

function assertIdentityUrn(value: string, kind: 'participant' | 'principal'): void {
  const matched = uuidV7Urn.exec(value);
  if (matched?.[1] !== kind) throw new Error(`invalid ${kind} identity URN`);
}

function assertUint64Text(value: string): void {
  if (!uint64Text.test(value) || BigInt(value) > 18_446_744_073_709_551_615n) {
    throw new Error('invalid uint64 decimal text');
  }
}

function assertTimestamp(value: string): void {
  const parsed = Date.parse(value);
  if (
    !utcMicros.test(value) ||
    Number.isNaN(parsed) ||
    new Date(parsed).toISOString() !== `${value.slice(0, 23)}Z`
  ) {
    throw new Error('invalid canonical timestamp');
  }
}

function validateIdentityCredentialPayload(
  payload: Buffer,
  context: CoseProtectedContext,
): IdentityCredentialPayload {
  if (
    context.schemaId !== identityCredentialCoseContext.schemaId ||
    context.purpose !== identityCredentialCoseContext.purpose
  ) {
    throw new Error('unsupported PC-CBOR-1 schema context');
  }
  const [entries, start] = readLength(payload, 0, 5);
  if (entries !== 9) throw new Error('IdentityCredentialV1 must contain exactly nine fields');
  let offset = start;
  let previousKey: Buffer | undefined;
  const values = new Map<number, string | number | Buffer>();
  for (let index = 0; index < entries; index += 1) {
    const key = readCanonicalIntegerKey(payload, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if (key.value === 2) {
      const value = readInteger(payload, offset);
      if (value.value < 0) throw new Error('schema ID must be unsigned');
      values.set(key.value, value.value);
      offset = value.next;
    } else if (key.value === 4) {
      const value = readByteString(payload, offset);
      values.set(key.value, value.bytes);
      offset = value.next;
    } else if ([1, 3, 5, 6, 7, 8, 9].includes(key.value)) {
      const value = readTextString(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else {
      throw new Error('unknown IdentityCredentialV1 member');
    }
  }
  if (offset !== payload.length) throw new Error('trailing PC-CBOR-1 bytes');
  const purpose = values.get(1);
  const schemaId = values.get(2);
  const schemaVersion = values.get(3);
  const schemaDigest = values.get(4);
  const participantId = values.get(5);
  const principalId = values.get(6);
  const authorityEpoch = values.get(7);
  const issuedAt = values.get(8);
  const expiresAt = values.get(9);
  if (
    purpose !== context.purpose ||
    schemaId !== context.schemaId ||
    schemaVersion !== identityCredentialSchemaVersion ||
    !Buffer.isBuffer(schemaDigest) ||
    schemaDigest.length !== identityCredentialSchemaDigest.length ||
    !timingSafeEqual(schemaDigest, identityCredentialSchemaDigest) ||
    typeof participantId !== 'string' ||
    typeof principalId !== 'string' ||
    typeof authorityEpoch !== 'string' ||
    typeof issuedAt !== 'string' ||
    typeof expiresAt !== 'string'
  ) {
    throw new Error('IdentityCredentialV1 schema validation failed');
  }
  assertIdentityUrn(participantId, 'participant');
  assertIdentityUrn(principalId, 'principal');
  assertUint64Text(authorityEpoch);
  assertTimestamp(issuedAt);
  assertTimestamp(expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new Error('IdentityCredentialV1 validity is empty');
  }
  return { participantId, principalId, authorityEpoch, issuedAt, expiresAt };
}

export function decodeIdentityCredentialPayload(payload: Buffer): IdentityCredentialPayload {
  return validateIdentityCredentialPayload(payload, identityCredentialCoseContext);
}

function encodeLength(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  if (length <= 0xffff) {
    const encoded = Buffer.alloc(3);
    encoded[0] = (major << 5) | 25;
    encoded.writeUInt16BE(length, 1);
    return encoded;
  }
  const encoded = Buffer.alloc(5);
  encoded[0] = (major << 5) | 26;
  encoded.writeUInt32BE(length, 1);
  return encoded;
}

function byteString(value: Buffer): Buffer {
  return Buffer.concat([encodeLength(2, value.length), value]);
}

function textString(value: string): Buffer {
  const encoded = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeLength(3, encoded.length), encoded]);
}

function unsignedInteger(value: number): Buffer {
  return encodeLength(0, value);
}

export function encodeIdentityCredentialPayload(value: IdentityCredentialPayload): Buffer {
  assertIdentityUrn(value.participantId, 'participant');
  assertIdentityUrn(value.principalId, 'principal');
  assertUint64Text(value.authorityEpoch);
  assertTimestamp(value.issuedAt);
  assertTimestamp(value.expiresAt);
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    throw new Error('IdentityCredentialV1 validity is empty');
  }
  const encoded = Buffer.concat([
    Buffer.from([0xa9, 0x01]),
    textString(identityCredentialCoseContext.purpose),
    Buffer.from([0x02]),
    unsignedInteger(identityCredentialCoseContext.schemaId),
    Buffer.from([0x03]),
    textString(identityCredentialSchemaVersion),
    Buffer.from([0x04]),
    byteString(identityCredentialSchemaDigest),
    Buffer.from([0x05]),
    textString(value.participantId),
    Buffer.from([0x06]),
    textString(value.principalId),
    Buffer.from([0x07]),
    textString(value.authorityEpoch),
    Buffer.from([0x08]),
    textString(value.issuedAt),
    Buffer.from([0x09]),
    textString(value.expiresAt),
  ]);
  validateIdentityCredentialPayload(encoded, identityCredentialCoseContext);
  return encoded;
}

function coseSignature(
  coseSign1: Buffer,
  expectedPayload: Buffer,
  expectedKeyId: Buffer,
  context: CoseProtectedContext,
): {
  readonly signature: Buffer;
  readonly sigStructure: Buffer;
} {
  let offset = 0;
  if (coseSign1[offset] === 0xd2) offset += 1;
  if (coseSign1[offset] !== 0x84) throw new Error('COSE_Sign1 must be a four-item array');
  offset += 1;
  const protectedHeader = readByteString(coseSign1, offset);
  offset = protectedHeader.next;
  validateProtectedHeader(protectedHeader.bytes, expectedKeyId, context);
  if (coseSign1[offset] !== 0xa0) throw new Error('COSE unprotected headers are forbidden');
  offset += 1;
  const payload = readByteString(coseSign1, offset);
  offset = payload.next;
  if (
    payload.bytes.length !== expectedPayload.length ||
    !timingSafeEqual(payload.bytes, expectedPayload)
  ) {
    throw new Error('COSE payload binding failed');
  }
  const signature = readByteString(coseSign1, offset);
  if (signature.next !== coseSign1.length || signature.bytes.length !== 64) {
    throw new Error('COSE signature must be IEEE-P1363 P-256 r||s');
  }
  return {
    signature: signature.bytes,
    sigStructure: Buffer.concat([
      Buffer.from([0x84, 0x6a]),
      Buffer.from('Signature1'),
      byteString(protectedHeader.bytes),
      Buffer.from([0x40]),
      byteString(payload.bytes),
    ]),
  };
}

export function verifyEs256P1363(
  publicKeySpkiDer: Buffer,
  signedBytes: Buffer,
  signature: Buffer,
): boolean {
  if (signature.length !== 64) return false;
  try {
    return verify(
      'sha256',
      signedBytes,
      {
        key: publicKeySpkiDer,
        format: 'der',
        type: 'spki',
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );
  } catch {
    return false;
  }
}

export function verifyCoseSign1Es256(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
  context: CoseProtectedContext,
): boolean {
  try {
    validateIdentityCredentialPayload(payload, context);
    return verifyBoundCoseSign1Es256(publicKeySpkiDer, payload, coseSign1, context);
  } catch {
    return false;
  }
}

/** Signs an already canonical IdentityCredentialV1 payload for local or HSM-backed adapters. */
export function signIdentityCredentialCoseSign1Es256(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  validateIdentityCredentialPayload(payload, identityCredentialCoseContext);
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03]),
    textString('application/openpc+cbor'),
    Buffer.from([0x04]),
    byteString(createHash('sha256').update(publicKeySpkiDer).digest()),
    Buffer.from([0x19, 0x03, 0xe9]),
    unsignedInteger(identityCredentialCoseContext.schemaId),
    Buffer.from([0x19, 0x03, 0xea]),
    textString(identityCredentialCoseContext.purpose),
  ]);
  const sigStructure = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from('Signature1'),
    byteString(protectedHeader),
    Buffer.from([0x40]),
    byteString(payload),
  ]);
  const signature = sign('sha256', sigStructure, {
    key: createPrivateKey({ key: privateKeyPkcs8Der, format: 'der', type: 'pkcs8' }),
    dsaEncoding: 'ieee-p1363',
  });
  const coseSign1 = Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    byteString(protectedHeader),
    Buffer.from([0xa0]),
    byteString(payload),
    byteString(signature),
  ]);
  if (!verifyCoseSign1Es256(publicKeySpkiDer, payload, coseSign1, identityCredentialCoseContext)) {
    throw new Error('generated COSE_Sign1 failed verification');
  }
  return coseSign1;
}

/**
 * Verifies the canonical COSE_Sign1 envelope, protected purpose/schema context,
 * trusted-key binding, exact payload bytes, and ES256 signature. The owning
 * schema module must validate its payload before calling this primitive.
 */
export function verifyBoundCoseSign1Es256(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
  context: CoseProtectedContext,
): boolean {
  try {
    const parsed = coseSignature(
      coseSign1,
      payload,
      createHash('sha256').update(publicKeySpkiDer).digest(),
      context,
    );
    return verifyEs256P1363(publicKeySpkiDer, parsed.sigStructure, parsed.signature);
  } catch {
    return false;
  }
}
export {
  configurationMutationOperations,
  configurationMutationOperation,
  configurationMutationForAction,
  type ConfigurationMutationOperation,
  type ConfigurationMutationOperationId,
} from './configuration-operations.js';
export * from './business-transition/signing-trust.js';
export { evidenceKeyId, signReceiptCose, verifyReceiptCose } from './business-transition/cose.js';
export { encodeReceiptStructure, decodeReceiptStructure } from './business-transition/payload.js';
export {
  encodeReceiptStructureV2,
  decodeReceiptStructureV2,
} from './business-transition/payload.js';
export { signReceiptCoseV2, verifyReceiptCoseV2 } from './business-transition/cose.js';
export type {
  BusinessTransitionReceipt,
  OutboxRef,
  EvidenceRef,
} from './business-transition/payload.js';
export { businessTransitionProfileForOperation } from './business-transition/profiles.js';
export type { BusinessTransitionProfile } from './business-transition/profiles.js';
export {
  encodeCommandCommitted,
  commandCommittedDigest,
  commandCommittedEventType,
  commandCommittedDataSchema,
} from './business-transition/command-event.js';
export { configurationRequestDigest } from './business-transition/request-digest.js';
export { encodeCbor as encodeCanonicalCbor } from './canonical-cbor.js';
export type { CborValue as CanonicalCborValue } from './canonical-cbor.js';
export {
  isExactSigningSecretReference,
  signingSecretReferenceMaxLength,
} from './business-transition/secret-reference.js';

export { controlMutationForAction } from './control-mutation-operations.js';
export { participantMutationOperations } from './participant-mutation-operations.js';
export { identityMutationOperations } from './identity-mutation-operations.js';
export { signingRoleProfiles, type SigningRole } from './signing-roles.js';
export {
  admittedReceiptSchemaVersion,
  encodeAdmittedReceipt,
  decodeAdmittedReceipt,
  verifyAdmittedReceiptCose,
} from './business-transition/admitted-receipt.js';

export {
  moduleRegistrationOperation,
  moduleLifecycleOperations,
  moduleMutationOperation,
  type ModuleMutationOperationId,
} from './module-mutation-operations.js';

export {
  encodeIdentityAuthorityVector,
  encodeIdentityAuthorityScope,
  identityWorkloadRuntimeBindings,
  identityRuntimeContextBindings,
  identityApplicableDenyScopeSetDigest,
  encodeIdentityRuntimeAuthorityProfile,
  encodeIdentityRuntimeSnapshot,
  identitySemanticDigest,
  signIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
  verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
  signIdentityRuntimeAuthorityProfileCoseSign1Ed25519,
  type IdentityAuthorityEntry,
  type IdentityAuthorityVector,
  type IdentityRuntimeAuthorityProfile,
  type IdentitySnapshotActor,
  type IdentitySnapshotInput,
  type EncodedIdentitySnapshot,
} from './identity-snapshot.js';
export {
  runtimeInvocationCapabilities,
  type RuntimeInvocationCapability,
} from './runtime-invocation-capabilities.js';
export {
  encodeArchiveSinkProfile,
  decodeArchiveSinkProfile,
  encodeArchiveSinkReceipt,
  decodeArchiveSinkReceipt,
  archiveDigest,
  encodeProtectedArchiveSinkProfile,
  decodeProtectedArchiveSinkProfile,
  encodeProtectedArchiveSinkReceipt,
  decodeProtectedArchiveSinkReceipt,
  type ProtectedArchiveSinkProfileClaims,
  type ProtectedArchiveSinkReceiptClaims,
  type ArchiveSinkProfileClaims,
  type ArchiveSinkReceiptClaims,
} from './evidence-archive/codec.js';
export {
  signArchiveCose,
  verifyArchiveCose,
  archiveProtectedHeader,
} from './evidence-archive/cose.js';
export { evidenceArchiveProfiles } from './evidence-archive/generated.js';
export {
  encodeFactConsumerProfile,
  decodeFactConsumerProfile,
  factConsumerProfileDigest,
  factConsumerRetryAfterFailure,
  factConsumerSubscriptions,
  type FactConsumerProfile,
  type FactConsumerRetryDecision,
} from './fact-consumer/profile.js';
export {
  signFactConsumerProfile,
  verifyFactConsumerProfileSignature,
  verifyInstalledFactConsumerProfile,
  type InstalledFactConsumerProfile,
} from './fact-consumer/cose.js';

export * from './secret-recipient/profile.js';
export * from './notification-gateway/codec.js';
export * from './notification-gateway/worker-contract.js';
export * from './evidence-export/codec.js';
export { evidenceExportCoseContext } from './evidence-export/generated.js';
export {
  evidenceKmsAllocations,
  assertEvidenceKmsAllocations,
  type EvidenceKmsAllocation,
} from './evidence-kms/allocation.js';
export * from './evidence-kms/codec.js';
export { evidenceKmsCoseProfiles } from './evidence-kms/generated.js';
export * from './operations-configuration/site-document.js';
export * from './operations-configuration/secret-resolution.js';

export * from './notification-gateway/completion-worker-contract.js';
export * from './workload-renewal-operations.js';
export * from './workload-renewal/types.js';
export * from './workload-renewal/codec.js';
export * from './workload-renewal/cose.js';
export * from './workload-renewal/signing-trust.js';
