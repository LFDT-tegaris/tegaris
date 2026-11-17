import { createHash, timingSafeEqual, verify } from 'node:crypto';
import { TextDecoder } from 'node:util';

interface ByteString {
  readonly bytes: Buffer;
  readonly next: number;
}

interface TextString {
  readonly next: number;
  readonly value: string;
}

export const policyActivationAuthorizationCoseContext = Object.freeze({
  purpose: 'openpc:policy-activation-authorization:v1',
  schemaId: 22502,
});

export const policyActivationAuthorizationSchemaPreimage =
  'PolicyActivationAuthorizationV1|1:purpose:text|2:schemaId:uint|3:schemaVersion:text|4:schemaDigest:bstr32|5:participantId:participant-urn|6:checkerPrincipalId:principal-urn|7:checkerPrincipalEpoch:uint64-text|8:operationId:POL-OP-ACTIVATE|9:actionIntentId:ACT-POLICY_ACTIVATE_RELEASE-V1|10:candidateDigest:bstr32|11:approvalRequestId:uuidv7|12:aggregateType:policy-activation|13:aggregateId:uuidv7|14:aggregateVersion:uint64-text|15:decision:APPROVE|16:issuedAt:rfc3339-micros|17:expiresAt:rfc3339-micros';

export const policyActivationAuthorizationSchemaDigest = createHash('sha256')
  .update(policyActivationAuthorizationSchemaPreimage)
  .digest();

export interface PolicyActivationAuthorizationPayload {
  readonly participantId: string;
  readonly checkerPrincipalId: string;
  readonly checkerPrincipalEpoch: string;
  readonly operationId: 'POL-OP-ACTIVATE';
  readonly actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1';
  readonly candidateDigest: Buffer;
  readonly approvalRequestId: string;
  readonly aggregateType: 'policy-activation';
  readonly aggregateId: string;
  readonly aggregateVersion: string;
  readonly decision: 'APPROVE';
  readonly issuedAt: string;
  readonly expiresAt: string;
}

const identityUrn =
  /^urn:openpc:(participant|principal):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uint64Text = /^(0|[1-9][0-9]*)$/u;
const utcMicros = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/u;
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
  return { next: end, value: utf8Decoder.decode(input.subarray(start, end)) };
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

function readCanonicalIntegerKey(
  input: Buffer,
  offset: number,
  previous: Buffer | undefined,
): { readonly encoded: Buffer; readonly next: number; readonly value: number } {
  const key = readInteger(input, offset);
  const encoded = input.subarray(offset, key.next);
  if (
    previous !== undefined &&
    (previous.length > encoded.length ||
      (previous.length === encoded.length && Buffer.compare(previous, encoded) >= 0))
  ) {
    throw new Error('non-canonical CBOR map order');
  }
  return { encoded, next: key.next, value: key.value };
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

function assertIdentityUrn(value: string, kind: 'participant' | 'principal'): void {
  if (identityUrn.exec(value)?.[1] !== kind) throw new Error(`invalid ${kind} identity URN`);
}

function assertUint64(value: string): void {
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

function assertPayload(value: PolicyActivationAuthorizationPayload): void {
  assertIdentityUrn(value.participantId, 'participant');
  assertIdentityUrn(value.checkerPrincipalId, 'principal');
  assertUint64(value.checkerPrincipalEpoch);
  if (
    value.operationId !== 'POL-OP-ACTIVATE' ||
    value.actionIntentId !== 'ACT-POLICY_ACTIVATE_RELEASE-V1' ||
    value.candidateDigest.length !== 32 ||
    !uuidV7.test(value.approvalRequestId) ||
    value.aggregateType !== 'policy-activation' ||
    !uuidV7.test(value.aggregateId) ||
    value.decision !== 'APPROVE'
  ) {
    throw new Error('PolicyActivationAuthorizationV1 semantic validation failed');
  }
  assertUint64(value.aggregateVersion);
  assertTimestamp(value.issuedAt);
  assertTimestamp(value.expiresAt);
  if (Date.parse(value.expiresAt) <= Date.parse(value.issuedAt)) {
    throw new Error('PolicyActivationAuthorizationV1 validity is empty');
  }
}

export function decodePolicyActivationAuthorizationPayload(
  payload: Buffer,
): PolicyActivationAuthorizationPayload {
  const [entries, start] = readLength(payload, 0, 5);
  if (entries !== 17) throw new Error('PolicyActivationAuthorizationV1 field count');
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
    } else if ([4, 10].includes(key.value)) {
      const value = readByteString(payload, offset);
      values.set(key.value, value.bytes);
      offset = value.next;
    } else if ([1, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17].includes(key.value)) {
      const value = readTextString(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else {
      throw new Error('unknown PolicyActivationAuthorizationV1 member');
    }
  }
  if (offset !== payload.length) throw new Error('trailing PC-CBOR-1 bytes');
  const schemaDigest = values.get(4);
  const candidateDigest = values.get(10);
  if (
    values.get(1) !== policyActivationAuthorizationCoseContext.purpose ||
    values.get(2) !== policyActivationAuthorizationCoseContext.schemaId ||
    values.get(3) !== '1.0.0' ||
    !Buffer.isBuffer(schemaDigest) ||
    !schemaDigest.equals(policyActivationAuthorizationSchemaDigest) ||
    !Buffer.isBuffer(candidateDigest)
  ) {
    throw new Error('PolicyActivationAuthorizationV1 schema validation failed');
  }
  const decoded = {
    participantId: String(values.get(5)),
    checkerPrincipalId: String(values.get(6)),
    checkerPrincipalEpoch: String(values.get(7)),
    operationId: String(values.get(8)),
    actionIntentId: String(values.get(9)),
    candidateDigest,
    approvalRequestId: String(values.get(11)),
    aggregateType: String(values.get(12)),
    aggregateId: String(values.get(13)),
    aggregateVersion: String(values.get(14)),
    decision: String(values.get(15)),
    issuedAt: String(values.get(16)),
    expiresAt: String(values.get(17)),
  } as PolicyActivationAuthorizationPayload;
  assertPayload(decoded);
  return decoded;
}

export function encodePolicyActivationAuthorizationPayload(
  value: PolicyActivationAuthorizationPayload,
): Buffer {
  assertPayload(value);
  const encoded = Buffer.concat([
    Buffer.from([0xb1, 0x01]),
    textString(policyActivationAuthorizationCoseContext.purpose),
    Buffer.from([0x02]),
    encodeLength(0, policyActivationAuthorizationCoseContext.schemaId),
    Buffer.from([0x03]),
    textString('1.0.0'),
    Buffer.from([0x04]),
    byteString(policyActivationAuthorizationSchemaDigest),
    Buffer.from([0x05]),
    textString(value.participantId),
    Buffer.from([0x06]),
    textString(value.checkerPrincipalId),
    Buffer.from([0x07]),
    textString(value.checkerPrincipalEpoch),
    Buffer.from([0x08]),
    textString(value.operationId),
    Buffer.from([0x09]),
    textString(value.actionIntentId),
    Buffer.from([0x0a]),
    byteString(value.candidateDigest),
    Buffer.from([0x0b]),
    textString(value.approvalRequestId),
    Buffer.from([0x0c]),
    textString(value.aggregateType),
    Buffer.from([0x0d]),
    textString(value.aggregateId),
    Buffer.from([0x0e]),
    textString(value.aggregateVersion),
    Buffer.from([0x0f]),
    textString(value.decision),
    Buffer.from([0x10]),
    textString(value.issuedAt),
    Buffer.from([0x11]),
    textString(value.expiresAt),
  ]);
  decodePolicyActivationAuthorizationPayload(encoded);
  return encoded;
}

function validateProtectedHeader(protectedHeader: Buffer, expectedKeyId: Buffer): void {
  const [entries, start] = readLength(protectedHeader, 0, 5);
  let offset = start;
  let previousKey: Buffer | undefined;
  const values = new Map<number, string | number | Buffer>();
  for (let index = 0; index < entries; index += 1) {
    const key = readCanonicalIntegerKey(protectedHeader, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if ([1, 1001].includes(key.value)) {
      const value = readInteger(protectedHeader, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else if (key.value === 3 || key.value === 1002) {
      const value = readTextString(protectedHeader, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else if (key.value === 4) {
      const value = readByteString(protectedHeader, offset);
      values.set(key.value, value.bytes);
      offset = value.next;
    } else {
      throw new Error('unknown COSE protected header');
    }
  }
  const keyId = values.get(4);
  if (
    entries !== 5 ||
    offset !== protectedHeader.length ||
    values.get(1) !== -7 ||
    values.get(3) !== 'application/openpc+cbor' ||
    !Buffer.isBuffer(keyId) ||
    keyId.length !== expectedKeyId.length ||
    !timingSafeEqual(keyId, expectedKeyId) ||
    values.get(1001) !== policyActivationAuthorizationCoseContext.schemaId ||
    values.get(1002) !== policyActivationAuthorizationCoseContext.purpose
  ) {
    throw new Error('COSE protected header context is invalid');
  }
}

export function verifyPolicyActivationAuthorizationCose(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  try {
    decodePolicyActivationAuthorizationPayload(payload);
    let offset = coseSign1[0] === 0xd2 ? 1 : 0;
    if (coseSign1[offset] !== 0x84) throw new Error('COSE_Sign1 array required');
    offset += 1;
    const protectedHeader = readByteString(coseSign1, offset);
    offset = protectedHeader.next;
    validateProtectedHeader(
      protectedHeader.bytes,
      createHash('sha256').update(publicKeySpkiDer).digest(),
    );
    if (coseSign1[offset] !== 0xa0) throw new Error('COSE unprotected headers are forbidden');
    offset += 1;
    const signedPayload = readByteString(coseSign1, offset);
    offset = signedPayload.next;
    if (!signedPayload.bytes.equals(payload)) throw new Error('COSE payload binding failed');
    const signature = readByteString(coseSign1, offset);
    if (signature.next !== coseSign1.length || signature.bytes.length !== 64) {
      throw new Error('COSE signature shape is invalid');
    }
    return verify(
      'sha256',
      Buffer.concat([
        Buffer.from([0x84, 0x6a]),
        Buffer.from('Signature1'),
        byteString(protectedHeader.bytes),
        Buffer.from([0x40]),
        byteString(signedPayload.bytes),
      ]),
      { key: publicKeySpkiDer, format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' },
      signature.bytes,
    );
  } catch {
    return false;
  }
}
