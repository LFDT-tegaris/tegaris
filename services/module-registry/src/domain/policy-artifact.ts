import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

import { verifyBoundCoseSign1Es256 } from '@openpc/security-kernel';

export const policyArtifactCoseContext = Object.freeze({
  purpose: 'openpc:policy-artifact:v1',
  schemaId: 22503,
});

export const policyArtifactSchemaPreimage =
  'PolicyArtifactV1|1:purpose:text|2:schemaId:uint|3:schemaVersion:text|4:schemaDigest:bstr32|5:participantId:participant-urn|6:privacyDomainId:privacy-domain-urn|7:policySetId:policy-set-urn|8:semanticVersion:semver|9:policySchemaDigest:bstr32|10:semanticDigest:bstr32|11:dependencyClosureDigest:bstr32|12:semanticBytesDigest:bstr32';

export const policyArtifactSchemaDigest = createHash('sha256')
  .update(policyArtifactSchemaPreimage)
  .digest();

export interface PolicyArtifactPayload {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly policySetId: string;
  readonly semanticVersion: string;
  readonly policySchemaDigest: Buffer;
  readonly semanticDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
  readonly semanticBytesDigest: Buffer;
}

export interface TrustedPolicyArtifactSigner {
  readonly publicKeySpkiDer: Buffer;
}

interface BytesValue {
  readonly bytes: Buffer;
  readonly next: number;
}

interface TextValue {
  readonly value: string;
  readonly next: number;
}

const participantUrn =
  /^urn:openpc:participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const privacyDomainUrn =
  /^urn:openpc:privacy-domain:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const policySetUrn =
  /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const semanticVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

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

function readBytes(input: Buffer, offset: number): BytesValue {
  const [length, start] = readLength(input, offset, 2);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR byte string');
  return { bytes: input.subarray(start, end), next: end };
}

function readText(input: Buffer, offset: number): TextValue {
  const [length, start] = readLength(input, offset, 3);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR text string');
  return { value: utf8Decoder.decode(input.subarray(start, end)), next: end };
}

function readUnsigned(
  input: Buffer,
  offset: number,
): { readonly value: number; readonly next: number } {
  const [value, next] = readLength(input, offset, 0);
  return { value, next };
}

function readCanonicalKey(
  input: Buffer,
  offset: number,
  previous: Buffer | undefined,
): { readonly encoded: Buffer; readonly value: number; readonly next: number } {
  const key = readUnsigned(input, offset);
  const encoded = input.subarray(offset, key.next);
  if (
    previous !== undefined &&
    (previous.length > encoded.length ||
      (previous.length === encoded.length && Buffer.compare(previous, encoded) >= 0))
  ) {
    throw new Error('non-canonical CBOR map order');
  }
  return { encoded, value: key.value, next: key.next };
}

function encodeLength(major: number, length: number): Buffer {
  if (!Number.isSafeInteger(length) || length < 0) throw new Error('invalid CBOR length');
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  if (length <= 0xffff) {
    const value = Buffer.alloc(3);
    value[0] = (major << 5) | 25;
    value.writeUInt16BE(length, 1);
    return value;
  }
  const value = Buffer.alloc(5);
  value[0] = (major << 5) | 26;
  value.writeUInt32BE(length, 1);
  return value;
}

function bytes(value: Buffer): Buffer {
  return Buffer.concat([encodeLength(2, value.length), value]);
}

function text(value: string): Buffer {
  const encoded = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeLength(3, encoded.length), encoded]);
}

function assertPayload(value: PolicyArtifactPayload): void {
  if (
    !participantUrn.test(value.participantId) ||
    !privacyDomainUrn.test(value.privacyDomainId) ||
    !policySetUrn.test(value.policySetId) ||
    !semanticVersion.test(value.semanticVersion) ||
    value.policySchemaDigest.length !== 32 ||
    value.semanticDigest.length !== 32 ||
    value.dependencyClosureDigest.length !== 32 ||
    value.semanticBytesDigest.length !== 32 ||
    !value.semanticDigest.equals(value.semanticBytesDigest)
  ) {
    throw new Error('PolicyArtifactV1 semantic validation failed');
  }
}

export function encodePolicyArtifactPayload(value: PolicyArtifactPayload): Buffer {
  assertPayload(value);
  const encoded = Buffer.concat([
    Buffer.from([0xac, 0x01]),
    text(policyArtifactCoseContext.purpose),
    Buffer.from([0x02]),
    encodeLength(0, policyArtifactCoseContext.schemaId),
    Buffer.from([0x03]),
    text('1.0.0'),
    Buffer.from([0x04]),
    bytes(policyArtifactSchemaDigest),
    Buffer.from([0x05]),
    text(value.participantId),
    Buffer.from([0x06]),
    text(value.privacyDomainId),
    Buffer.from([0x07]),
    text(value.policySetId),
    Buffer.from([0x08]),
    text(value.semanticVersion),
    Buffer.from([0x09]),
    bytes(value.policySchemaDigest),
    Buffer.from([0x0a]),
    bytes(value.semanticDigest),
    Buffer.from([0x0b]),
    bytes(value.dependencyClosureDigest),
    Buffer.from([0x0c]),
    bytes(value.semanticBytesDigest),
  ]);
  decodePolicyArtifactPayload(encoded);
  return encoded;
}

export function decodePolicyArtifactPayload(payload: Buffer): PolicyArtifactPayload {
  const [entries, start] = readLength(payload, 0, 5);
  if (entries !== 12) throw new Error('PolicyArtifactV1 field count');
  let offset = start;
  let previousKey: Buffer | undefined;
  const values = new Map<number, string | number | Buffer>();
  for (let index = 0; index < entries; index += 1) {
    const key = readCanonicalKey(payload, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if (key.value === 2) {
      const value = readUnsigned(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else if ([4, 9, 10, 11, 12].includes(key.value)) {
      const value = readBytes(payload, offset);
      values.set(key.value, value.bytes);
      offset = value.next;
    } else if ([1, 3, 5, 6, 7, 8].includes(key.value)) {
      const value = readText(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else {
      throw new Error('unknown PolicyArtifactV1 member');
    }
  }
  if (offset !== payload.length) throw new Error('trailing PC-CBOR-1 bytes');
  const schemaDigest = values.get(4);
  const policySchemaDigest = values.get(9);
  const semanticDigest = values.get(10);
  const dependencyClosureDigest = values.get(11);
  const semanticBytesDigest = values.get(12);
  if (
    values.get(1) !== policyArtifactCoseContext.purpose ||
    values.get(2) !== policyArtifactCoseContext.schemaId ||
    values.get(3) !== '1.0.0' ||
    !Buffer.isBuffer(schemaDigest) ||
    !schemaDigest.equals(policyArtifactSchemaDigest) ||
    !Buffer.isBuffer(policySchemaDigest) ||
    !Buffer.isBuffer(semanticDigest) ||
    !Buffer.isBuffer(dependencyClosureDigest) ||
    !Buffer.isBuffer(semanticBytesDigest)
  ) {
    throw new Error('PolicyArtifactV1 schema validation failed');
  }
  const decoded: PolicyArtifactPayload = {
    participantId: String(values.get(5)),
    privacyDomainId: String(values.get(6)),
    policySetId: String(values.get(7)),
    semanticVersion: String(values.get(8)),
    policySchemaDigest,
    semanticDigest,
    dependencyClosureDigest,
    semanticBytesDigest,
  };
  assertPayload(decoded);
  return decoded;
}

export function verifyPolicyArtifactCose(
  trustedSigners: readonly TrustedPolicyArtifactSigner[],
  payload: Buffer,
  coseSign1: Buffer,
): Buffer | undefined {
  decodePolicyArtifactPayload(payload);
  for (const signer of trustedSigners) {
    if (
      verifyBoundCoseSign1Es256(
        signer.publicKeySpkiDer,
        payload,
        coseSign1,
        policyArtifactCoseContext,
      )
    ) {
      return createHash('sha256').update(signer.publicKeySpkiDer).digest();
    }
  }
  return undefined;
}
