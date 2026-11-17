import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto';
import { TextDecoder } from 'node:util';

const MAX_CANONICAL_BYTES = 262_144;
const MAX_UINT64 = 18_446_744_073_709_551_615n;
// CBOR text carries U+FEFF as data, including at the start of a string.
const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const identityRuntimeExternalAad = Buffer.from(
  '7063706c616e653a636f73652d7369676e313a76320070632e636f73652e6964656e746974792d72756e74696d652e7632',
  'hex',
);

export const identityAuthContextAssertionCoseContext = Object.freeze({
  contentType: 'application/pc+cbor',
  externalAadHex: identityRuntimeExternalAad.toString('hex'),
  purpose: 'pc.cose.identity-runtime.v2',
  purposeId: 13,
  schemaId: 3002,
  schemaVersion: 2,
  signatureProfileVersion: 2,
});

export interface IdentityAuthContextAssertionPayload {
  readonly assertionId: string;
  readonly actorKeyDigest: Buffer;
  readonly actorKind: 0 | 1;
  readonly participantContextDigest: Buffer;
  readonly audienceDigest: Buffer;
  readonly senderBindingKind: 0 | 1 | 2 | 3 | 4;
  readonly assuranceProfileDigest: Buffer;
  readonly authorityVectorDigest: Buffer;
  readonly issuedAtNs: bigint;
  readonly expiresAtNs: bigint;
  readonly authenticationEvidenceDigest: Buffer;
  readonly senderCredentialBindingDigest?: Buffer;
}

interface ParsedBytes {
  readonly bytes: Buffer;
  readonly next: number;
}

interface ParsedUnsigned {
  readonly next: number;
  readonly value: bigint;
}

function readArgument(input: Buffer, offset: number, expectedMajor: number): ParsedUnsigned {
  const initial = input[offset];
  if (initial === undefined || initial >> 5 !== expectedMajor) {
    throw new Error('invalid CBOR type');
  }
  const additional = initial & 0x1f;
  if (additional < 24) return { next: offset + 1, value: BigInt(additional) };
  if (additional === 24) {
    const value = input[offset + 1];
    if (value === undefined || value < 24) throw new Error('non-canonical CBOR integer');
    return { next: offset + 2, value: BigInt(value) };
  }
  if (additional === 25) {
    if (offset + 3 > input.length) throw new Error('truncated CBOR integer');
    const value = input.readUInt16BE(offset + 1);
    if (value <= 0xff) throw new Error('non-canonical CBOR integer');
    return { next: offset + 3, value: BigInt(value) };
  }
  if (additional === 26) {
    if (offset + 5 > input.length) throw new Error('truncated CBOR integer');
    const value = input.readUInt32BE(offset + 1);
    if (value <= 0xffff) throw new Error('non-canonical CBOR integer');
    return { next: offset + 5, value: BigInt(value) };
  }
  if (additional === 27) {
    if (offset + 9 > input.length) throw new Error('truncated CBOR integer');
    const value = input.readBigUInt64BE(offset + 1);
    if (value <= 0xffff_ffffn) throw new Error('non-canonical CBOR integer');
    return { next: offset + 9, value };
  }
  throw new Error('indefinite or reserved CBOR argument');
}

function readLength(input: Buffer, offset: number, expectedMajor: number): [number, number] {
  const parsed = readArgument(input, offset, expectedMajor);
  if (parsed.value > BigInt(MAX_CANONICAL_BYTES)) throw new Error('CBOR item is too large');
  return [Number(parsed.value), parsed.next];
}

function readUnsigned(input: Buffer, offset: number): ParsedUnsigned {
  return readArgument(input, offset, 0);
}

function readSigned(
  input: Buffer,
  offset: number,
): { readonly next: number; readonly value: bigint } {
  const initial = input[offset];
  if (initial === undefined || (initial >> 5 !== 0 && initial >> 5 !== 1)) {
    throw new Error('CBOR integer required');
  }
  const major = initial >> 5;
  const parsed = readArgument(input, offset, major);
  return { next: parsed.next, value: major === 0 ? parsed.value : -1n - parsed.value };
}

function readBytes(input: Buffer, offset: number): ParsedBytes {
  const [length, start] = readLength(input, offset, 2);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR byte string');
  return { bytes: input.subarray(start, end), next: end };
}

function readText(
  input: Buffer,
  offset: number,
): { readonly next: number; readonly value: string } {
  const [length, start] = readLength(input, offset, 3);
  const end = start + length;
  if (end > input.length) throw new Error('truncated CBOR text string');
  return { next: end, value: utf8Decoder.decode(input.subarray(start, end)) };
}

function assertCanonicalOrder(previous: Buffer | undefined, current: Buffer): void {
  if (
    previous !== undefined &&
    (previous.length > current.length ||
      (previous.length === current.length && Buffer.compare(previous, current) >= 0))
  ) {
    throw new Error('non-canonical CBOR map order');
  }
}

function readMapKey(
  input: Buffer,
  offset: number,
  previous: Buffer | undefined,
): { readonly encoded: Buffer; readonly next: number; readonly value: number } {
  const parsed = readUnsigned(input, offset);
  if (parsed.value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR key is too large');
  const encoded = input.subarray(offset, parsed.next);
  assertCanonicalOrder(previous, encoded);
  return { encoded, next: parsed.next, value: Number(parsed.value) };
}

function encodeArgument(major: number, value: bigint): Buffer {
  if (value < 0n || value > MAX_UINT64) throw new Error('invalid uint64');
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  if (value <= 0xffn) return Buffer.from([(major << 5) | 24, Number(value)]);
  if (value <= 0xffffn) {
    const encoded = Buffer.alloc(3);
    encoded[0] = (major << 5) | 25;
    encoded.writeUInt16BE(Number(value), 1);
    return encoded;
  }
  if (value <= 0xffff_ffffn) {
    const encoded = Buffer.alloc(5);
    encoded[0] = (major << 5) | 26;
    encoded.writeUInt32BE(Number(value), 1);
    return encoded;
  }
  const encoded = Buffer.alloc(9);
  encoded[0] = (major << 5) | 27;
  encoded.writeBigUInt64BE(value, 1);
  return encoded;
}

function encodeBytes(value: Buffer): Buffer {
  return Buffer.concat([encodeArgument(2, BigInt(value.length)), value]);
}

function encodeText(value: string): Buffer {
  const encoded = Buffer.from(value, 'utf8');
  return Buffer.concat([encodeArgument(3, BigInt(encoded.length)), encoded]);
}

function encodeUnsigned(value: number | bigint): Buffer {
  return encodeArgument(0, BigInt(value));
}

function assertDigest(value: Buffer, name: string): void {
  if (!Buffer.isBuffer(value) || value.length !== 32) throw new Error(`${name} must be bytes32`);
}

function assertEd25519Key(key: KeyObject, name: string): void {
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${name} must be Ed25519`);
  }
}

function assertAssertion(value: IdentityAuthContextAssertionPayload): void {
  const assertionBytes = Buffer.from(value.assertionId, 'utf8');
  if (
    assertionBytes.length < 1 ||
    assertionBytes.length > 160 ||
    value.assertionId.normalize('NFC') !== value.assertionId
  ) {
    throw new Error('invalid assertionId');
  }
  for (const [name, digest] of [
    ['actorKeyDigest', value.actorKeyDigest],
    ['participantContextDigest', value.participantContextDigest],
    ['audienceDigest', value.audienceDigest],
    ['assuranceProfileDigest', value.assuranceProfileDigest],
    ['authorityVectorDigest', value.authorityVectorDigest],
    ['authenticationEvidenceDigest', value.authenticationEvidenceDigest],
  ] as const) {
    assertDigest(digest, name);
  }
  if (value.senderCredentialBindingDigest !== undefined) {
    assertDigest(value.senderCredentialBindingDigest, 'senderCredentialBindingDigest');
  }
  if (
    (value.actorKind !== 0 && value.actorKind !== 1) ||
    ![0, 1, 2, 3, 4].includes(value.senderBindingKind)
  ) {
    throw new Error('invalid identity runtime enum');
  }
  if (
    typeof value.issuedAtNs !== 'bigint' ||
    typeof value.expiresAtNs !== 'bigint' ||
    value.issuedAtNs < 0n ||
    value.issuedAtNs > MAX_UINT64 ||
    value.expiresAtNs < 0n ||
    value.expiresAtNs > MAX_UINT64 ||
    value.issuedAtNs >= value.expiresAtNs
  ) {
    throw new Error('identity auth context validity is empty');
  }
}

export function encodeIdentityAuthContextAssertionPayload(
  value: IdentityAuthContextAssertionPayload,
): Buffer {
  assertAssertion(value);
  const fields = [
    encodeUnsigned(0),
    encodeText(value.assertionId),
    encodeUnsigned(1),
    encodeBytes(value.actorKeyDigest),
    encodeUnsigned(2),
    encodeUnsigned(value.actorKind),
    encodeUnsigned(3),
    encodeBytes(value.participantContextDigest),
    encodeUnsigned(4),
    encodeBytes(value.audienceDigest),
    encodeUnsigned(5),
    encodeUnsigned(value.senderBindingKind),
    encodeUnsigned(6),
    encodeBytes(value.assuranceProfileDigest),
    encodeUnsigned(7),
    encodeBytes(value.authorityVectorDigest),
    encodeUnsigned(8),
    encodeUnsigned(value.issuedAtNs),
    encodeUnsigned(9),
    encodeUnsigned(value.expiresAtNs),
    encodeUnsigned(10),
    encodeBytes(value.authenticationEvidenceDigest),
  ];
  if (value.senderCredentialBindingDigest !== undefined) {
    fields.push(encodeUnsigned(11), encodeBytes(value.senderCredentialBindingDigest));
  }
  const encoded = Buffer.concat([
    encodeArgument(5, value.senderCredentialBindingDigest === undefined ? 11n : 12n),
    ...fields,
  ]);
  if (encoded.length > MAX_CANONICAL_BYTES) throw new Error('identity auth context is too large');
  return encoded;
}

export function decodeIdentityAuthContextAssertionPayload(
  payload: Buffer,
): IdentityAuthContextAssertionPayload {
  if (!Buffer.isBuffer(payload) || payload.length > MAX_CANONICAL_BYTES) {
    throw new Error('invalid identity auth context payload');
  }
  const [entries, start] = readLength(payload, 0, 5);
  if (entries !== 11 && entries !== 12) {
    throw new Error('identity auth context field count is invalid');
  }
  let offset = start;
  let previousKey: Buffer | undefined;
  const values = new Map<number, string | bigint | Buffer>();
  for (let index = 0; index < entries; index += 1) {
    const key = readMapKey(payload, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if (key.value === 0) {
      const value = readText(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else if ([1, 3, 4, 6, 7, 10, 11].includes(key.value)) {
      const value = readBytes(payload, offset);
      values.set(key.value, Buffer.from(value.bytes));
      offset = value.next;
    } else if ([2, 5, 8, 9].includes(key.value)) {
      const value = readUnsigned(payload, offset);
      values.set(key.value, value.value);
      offset = value.next;
    } else {
      throw new Error('unknown identity auth context field');
    }
  }
  if (offset !== payload.length) throw new Error('trailing identity auth context bytes');
  const decoded: IdentityAuthContextAssertionPayload = {
    assertionId: values.get(0) as string,
    actorKeyDigest: values.get(1) as Buffer,
    actorKind: Number(values.get(2)) as 0 | 1,
    participantContextDigest: values.get(3) as Buffer,
    audienceDigest: values.get(4) as Buffer,
    senderBindingKind: Number(values.get(5)) as 0 | 1 | 2 | 3 | 4,
    assuranceProfileDigest: values.get(6) as Buffer,
    authorityVectorDigest: values.get(7) as Buffer,
    issuedAtNs: values.get(8) as bigint,
    expiresAtNs: values.get(9) as bigint,
    authenticationEvidenceDigest: values.get(10) as Buffer,
    ...(values.has(11) ? { senderCredentialBindingDigest: values.get(11) as Buffer } : {}),
  };
  assertAssertion(decoded);
  if (!encodeIdentityAuthContextAssertionPayload(decoded).equals(payload)) {
    throw new Error('identity auth context is not canonical');
  }
  return decoded;
}

function validateCriticalLabels(input: Buffer, offset: number): number {
  const [entries, start] = readLength(input, offset, 4);
  if (entries !== 4) throw new Error('COSE critical labels are invalid');
  let next = start;
  for (const expected of [100n, 101n, 102n, 103n]) {
    const parsed = readUnsigned(input, next);
    if (parsed.value !== expected) throw new Error('COSE critical labels are invalid');
    next = parsed.next;
  }
  return next;
}

function validateProtectedHeader(
  protectedHeader: Buffer,
  expectedKeyId: Buffer,
  schemaId: 3002 | 3003 | 3004 | 3010 = 3002,
): void {
  const [entries, start] = readLength(protectedHeader, 0, 5);
  if (entries !== 8) throw new Error('COSE protected header field count is invalid');
  let offset = start;
  let previousKey: Buffer | undefined;
  const seen = new Set<number>();
  for (let index = 0; index < entries; index += 1) {
    const key = readMapKey(protectedHeader, offset, previousKey);
    previousKey = key.encoded;
    offset = key.next;
    if (seen.has(key.value)) throw new Error('duplicate COSE protected header');
    seen.add(key.value);
    if (key.value === 1) {
      const value = readSigned(protectedHeader, offset);
      if (value.value !== -8n) throw new Error('COSE algorithm is invalid');
      offset = value.next;
    } else if (key.value === 2) {
      offset = validateCriticalLabels(protectedHeader, offset);
    } else if (key.value === 3) {
      const value = readText(protectedHeader, offset);
      if (value.value !== identityAuthContextAssertionCoseContext.contentType) {
        throw new Error('COSE content type is invalid');
      }
      offset = value.next;
    } else if (key.value === 4) {
      const value = readBytes(protectedHeader, offset);
      if (
        value.bytes.length !== expectedKeyId.length ||
        !timingSafeEqual(value.bytes, expectedKeyId)
      ) {
        throw new Error('COSE key ID is invalid');
      }
      offset = value.next;
    } else if (key.value === 102) {
      const value = readText(protectedHeader, offset);
      if (value.value !== identityAuthContextAssertionCoseContext.purpose)
        throw new Error('COSE purpose is invalid');
      offset = value.next;
    } else if ([100, 101, 103].includes(key.value)) {
      const value = readUnsigned(protectedHeader, offset);
      const expected = {
        100: schemaId,
        101: identityAuthContextAssertionCoseContext.schemaVersion,
        102: identityAuthContextAssertionCoseContext.purposeId,
        103: identityAuthContextAssertionCoseContext.signatureProfileVersion,
      }[key.value]!;
      if (value.value !== BigInt(expected)) throw new Error('COSE protected context is invalid');
      offset = value.next;
    } else {
      throw new Error('unknown COSE protected header');
    }
  }
  if (offset !== protectedHeader.length) throw new Error('trailing COSE protected header bytes');
}

function identityKeyId(publicKeySpkiDer: Buffer): Buffer {
  // RFC 8410 Ed25519 SPKI has one encoding. Node's DER parser otherwise accepts
  // trailing bytes, creating multiple key IDs for the same verification key.
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  if (publicKeySpkiDer.length !== 44 || !publicKeySpkiDer.subarray(0, 12).equals(prefix)) {
    throw new Error('identity runtime public key must be canonical Ed25519 SPKI');
  }
  return Buffer.from(`sha256:${createHash('sha256').update(publicKeySpkiDer).digest('hex')}`);
}

/** Exact CANON-CONTRACT-001 semantic envelope, carried as the COSE payload. */
function canonicalEnvelope(schemaId: number, payload: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0xa4, 0, 1, 1]),
    encodeUnsigned(schemaId),
    Buffer.from([2, 2, 3]),
    payload,
  ]);
}

function protectedHeader(
  publicKeySpkiDer: Buffer,
  schemaId: 3002 | 3003 | 3004 | 3010 = 3002,
): Buffer {
  const keyId = identityKeyId(publicKeySpkiDer);
  return Buffer.concat([
    Buffer.from([0xa8, 0x01, 0x27, 0x02, 0x84]),
    encodeUnsigned(100),
    encodeUnsigned(101),
    encodeUnsigned(102),
    encodeUnsigned(103),
    Buffer.from([0x03]),
    encodeText(identityAuthContextAssertionCoseContext.contentType),
    Buffer.from([0x04]),
    encodeBytes(keyId),
    encodeUnsigned(100),
    encodeUnsigned(schemaId),
    encodeUnsigned(101),
    encodeUnsigned(identityAuthContextAssertionCoseContext.schemaVersion),
    encodeUnsigned(102),
    encodeText(identityAuthContextAssertionCoseContext.purpose),
    encodeUnsigned(103),
    encodeUnsigned(identityAuthContextAssertionCoseContext.signatureProfileVersion),
  ]);
}

function signatureStructure(header: Buffer, payload: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0x84]),
    encodeText('Signature1'),
    encodeBytes(header),
    encodeBytes(identityRuntimeExternalAad),
    encodeBytes(payload),
  ]);
}

function coseSignature(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
  schemaId: 3002 | 3003 | 3004 | 3010 = 3002,
): { readonly signature: Buffer; readonly structure: Buffer } {
  let offset = coseSign1[0] === 0xd2 ? 1 : 0;
  if (coseSign1[offset] !== 0x84) throw new Error('COSE_Sign1 must be a four-item array');
  offset += 1;
  const header = readBytes(coseSign1, offset);
  offset = header.next;
  validateProtectedHeader(header.bytes, identityKeyId(publicKeySpkiDer), schemaId);
  if (coseSign1[offset] !== 0xa0) throw new Error('COSE unprotected headers are forbidden');
  offset += 1;
  const signedPayload = readBytes(coseSign1, offset);
  offset = signedPayload.next;
  const canonical = canonicalEnvelope(schemaId, payload);
  if (
    signedPayload.bytes.length !== canonical.length ||
    !timingSafeEqual(signedPayload.bytes, canonical)
  ) {
    throw new Error('COSE payload binding failed');
  }
  const signature = readBytes(coseSign1, offset);
  if (signature.next !== coseSign1.length || signature.bytes.length !== 64) {
    throw new Error('COSE signature must be 64-byte Ed25519');
  }
  return { signature: signature.bytes, structure: signatureStructure(header.bytes, canonical) };
}

export function signIdentityAuthContextAssertionCoseSign1Ed25519(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  decodeIdentityAuthContextAssertionPayload(payload);
  return signIdentityRuntimeProfile(3002, privateKeyPkcs8Der, publicKeySpkiDer, payload);
}

export function signIdentityRuntimeProfile(
  schemaId: 3002 | 3003 | 3004 | 3010,
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  const privateKey = createPrivateKey({ key: privateKeyPkcs8Der, format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey({ key: publicKeySpkiDer, format: 'der', type: 'spki' });
  assertEd25519Key(privateKey, 'identity runtime private key');
  assertEd25519Key(publicKey, 'identity runtime public key');
  const header = protectedHeader(publicKeySpkiDer, schemaId);
  const canonical = canonicalEnvelope(schemaId, payload);
  const signature = sign(null, signatureStructure(header, canonical), privateKey);
  const coseSign1 = Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    encodeBytes(header),
    Buffer.from([0xa0]),
    encodeBytes(canonical),
    encodeBytes(signature),
  ]);
  if (!verifyIdentityRuntimeProfile(schemaId, publicKeySpkiDer, payload, coseSign1)) {
    throw new Error('generated identity auth context COSE_Sign1 failed verification');
  }
  return coseSign1;
}

export function verifyIdentityAuthContextAssertionCoseSign1Ed25519(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  try {
    decodeIdentityAuthContextAssertionPayload(payload);
    return verifyIdentityRuntimeProfile(3002, publicKeySpkiDer, payload, coseSign1);
  } catch {
    return false;
  }
}

export function verifyIdentityRuntimeProfile(
  schemaId: 3002 | 3003 | 3004 | 3010,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  try {
    const publicKey = createPublicKey({ key: publicKeySpkiDer, format: 'der', type: 'spki' });
    assertEd25519Key(publicKey, 'identity runtime public key');
    const parsed = coseSignature(publicKeySpkiDer, payload, coseSign1, schemaId);
    return verify(null, parsed.structure, publicKey, parsed.signature);
  } catch {
    return false;
  }
}

/** pc.identity.runtime-actor-projection@2 binds authority digests;
 * it is not an authentication assertion and cannot mint a capability. */
export interface IdentityRuntimeActorProjection {
  readonly actorKeyDigest: Buffer;
  readonly actorKind: 0 | 1;
  readonly participantContextDigest: Buffer;
  readonly roleAssignmentSetDigest: Buffer;
  readonly participantEnvelopeDigest: Buffer;
  readonly authorityVectorDigest: Buffer;
}

export function encodeIdentityRuntimeActorProjection(
  input: IdentityRuntimeActorProjection,
): Buffer {
  if (input.actorKind !== 0 && input.actorKind !== 1) throw new Error('invalid actor kind');
  const digests = [
    input.actorKeyDigest,
    input.participantContextDigest,
    input.roleAssignmentSetDigest,
    input.participantEnvelopeDigest,
    input.authorityVectorDigest,
  ];
  for (const value of digests) assertDigest(value, 'runtime actor projection digest');
  return Buffer.concat([
    Buffer.from([0xa6, 0]),
    encodeBytes(input.actorKeyDigest),
    Buffer.from([1]),
    encodeUnsigned(input.actorKind),
    ...digests.slice(1).flatMap((value, index) => [encodeUnsigned(index + 2), encodeBytes(value)]),
  ]);
}

export function decodeIdentityRuntimeActorProjection(
  input: Buffer,
): IdentityRuntimeActorProjection {
  if (!Buffer.isBuffer(input) || input.length > MAX_CANONICAL_BYTES || input[0] !== 0xa6)
    throw new Error('invalid actor projection');
  let offset = 1;
  const digests: Buffer[] = [];
  let kind = -1;
  for (let index = 0; index < 6; index += 1) {
    const key = readUnsigned(input, offset);
    if (key.value !== BigInt(index)) throw new Error('invalid actor projection field');
    offset = key.next;
    if (index === 1) {
      const value = readUnsigned(input, offset);
      if (value.value > 1n) throw new Error('invalid actor kind');
      kind = Number(value.value);
      offset = value.next;
    } else {
      const value = readBytes(input, offset);
      assertDigest(value.bytes, 'runtime actor projection digest');
      digests.push(Buffer.from(value.bytes));
      offset = value.next;
    }
  }
  if (offset !== input.length) throw new Error('trailing actor projection bytes');
  return {
    actorKeyDigest: digests[0]!,
    actorKind: kind as 0 | 1,
    participantContextDigest: digests[1]!,
    roleAssignmentSetDigest: digests[2]!,
    participantEnvelopeDigest: digests[3]!,
    authorityVectorDigest: digests[4]!,
  };
}

export function signIdentityRuntimeActorProjectionCoseSign1Ed25519(
  privateKeyPkcs8Der: Buffer,
  publicKeySpkiDer: Buffer,
  payload: Buffer,
): Buffer {
  decodeIdentityRuntimeActorProjection(payload);
  return signIdentityRuntimeProfile(3003, privateKeyPkcs8Der, publicKeySpkiDer, payload);
}

export function verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(
  publicKeySpkiDer: Buffer,
  payload: Buffer,
  coseSign1: Buffer,
): boolean {
  try {
    decodeIdentityRuntimeActorProjection(payload);
  } catch {
    return false;
  }
  return verifyIdentityRuntimeProfile(3003, publicKeySpkiDer, payload, coseSign1);
}
