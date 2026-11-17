import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { openPcUrnSchema } from '../configuration/resource-contracts.js';
import { EvidenceCustodyError, digest, sequence } from './segment.js';

/** The existing OPENPC-CRYPTO-PROFILE-1 field-encryption parameters, with a
 * separate notification domain. This profile does not authorize a route or key. */
export const notificationPayloadEncryptionProfile = Object.freeze({
  version: 'OPENPC_NOTIFICATION_PAYLOAD_ENCRYPTION_V1',
  algorithm: 'AES-256-GCM',
  nonceBytes: 12,
  tagBytes: 16,
  maximumPlaintextBytes: 65536,
  aadDomain: 'openpc:notification-payload:v1',
  encoding: 'CANONICAL_JSON_UTF8',
});
export const notificationPayloadEncryptionProfileDigest = sha256(
  notificationPayloadEncryptionProfile,
);
const maximumEnvelopeBytes = 128 * 1024;
const uuid = z.uuidv7().refine((value) => value === value.toLowerCase());
const ordinal = sequence.refine((value) => value !== '0');
const reference = openPcUrnSchema.refine((value) => value === value.trim());
// Immutable digest of the authenticated wrapped-object-key record, never a
// provider alias or an active/latest selector. The key owner retains that record.
const keyId = digest;

/** Every field comes from the immutable occurrence, admitted routing/template
 * revision and Evidence object/key owners. No field is delivery authority. In
 * particular, a received event cannot supply the expected decryption binding. */
export const notificationPayloadBinding = z.strictObject({
  environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  participantId: uuid,
  privacyDomainId: uuid,
  payloadObjectId: uuid,
  objectVersion: z.literal('1'),
  notificationOccurrenceRef: reference,
  routingProfileDigest: digest,
  templateDigest: digest,
  recipientSetDigest: digest,
  redactionProfileDigest: digest,
  preferenceGeneration: ordinal,
  payloadDigest: digest,
  keyId,
});
export type NotificationPayloadBinding = z.infer<typeof notificationPayloadBinding>;

/** Unwrapped DEK bytes in the owning workload's memory. The Evidence/KMS owner
 * must admit the exact immutable key identity before calling this primitive;
 * this is neither a resolver callback nor a replacement for key custody,
 * revocation, non-exportable KEK wrapping or destruction/readback evidence. */
export interface NotificationPayloadKeyMaterial {
  readonly keyId: string;
  readonly bytes: Buffer;
}
const header = z.strictObject({
  version: z.literal('OPENPC_NOTIFICATION_PAYLOAD_V1'),
  encryptionProfileDigest: z.literal(notificationPayloadEncryptionProfileDigest),
  binding: notificationPayloadBinding,
});
const envelope = z.strictObject({
  header,
  nonce: z.string().regex(/^[0-9a-f]{24}$/u),
  ciphertext: z.string().min(4).max(87384),
  tag: z.string().regex(/^[0-9a-f]{32}$/u),
});
const metadata = (binding: NotificationPayloadBinding) => ({
  version: 'OPENPC_NOTIFICATION_PAYLOAD_V1' as const,
  encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
  binding,
});
const aad = (value: z.infer<typeof header>) =>
  Buffer.concat([
    Buffer.from(`${notificationPayloadEncryptionProfile.aadDomain}\0`, 'utf8'),
    Buffer.from(canonicalJson(value), 'utf8'),
  ]);
function parseBinding(value: unknown) {
  const result = notificationPayloadBinding.safeParse(value);
  if (!result.success) throw new EvidenceCustodyError('INVALID');
  return result.data;
}
function exactKey(material: NotificationPayloadKeyMaterial, binding: NotificationPayloadBinding) {
  if (
    material.keyId !== binding.keyId ||
    !Buffer.isBuffer(material.bytes) ||
    material.bytes.length !== 32
  )
    throw new EvidenceCustodyError('UNAVAILABLE');
  return material.bytes;
}

/** Structural inspection only; authentication requires openNotificationPayload
 * with the durable owner's complete expected binding and original object digest. */
export function inspectNotificationPayload(bytes: Buffer) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > maximumEnvelopeBytes)
    throw new EvidenceCustodyError('CAPACITY');
  try {
    const parsed = envelope.parse(JSON.parse(bytes.toString('utf8')));
    if (!Buffer.from(canonicalJson(parsed)).equals(bytes)) throw new Error();
    const ciphertext = Buffer.from(parsed.ciphertext, 'base64');
    if (
      ciphertext.toString('base64') !== parsed.ciphertext ||
      ciphertext.length === 0 ||
      ciphertext.length > notificationPayloadEncryptionProfile.maximumPlaintextBytes
    )
      throw new Error();
    return {
      header: parsed.header,
      encryptionContextDigest: sha256(aad(parsed.header)),
      encryptedObjectDigest: sha256(bytes),
      nonce: Buffer.from(parsed.nonce, 'hex'),
      ciphertext,
      tag: Buffer.from(parsed.tag, 'hex'),
    };
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}

/** Encrypt already authorized/minimized bytes. Persist the returned original
 * envelope with its immutable object/key/reference identity before publication.
 * A retry reads that envelope; it does not reseal an existing object identity. */
export function sealNotificationPayload(
  input: NotificationPayloadBinding,
  plaintext: Buffer,
  material: NotificationPayloadKeyMaterial,
) {
  const binding = parseBinding(input);
  const key = exactKey(material, binding);
  if (
    !Buffer.isBuffer(plaintext) ||
    plaintext.length === 0 ||
    plaintext.length > notificationPayloadEncryptionProfile.maximumPlaintextBytes
  )
    throw new EvidenceCustodyError('CAPACITY');
  if (sha256(plaintext) !== binding.payloadDigest) throw new EvidenceCustodyError('INTEGRITY');
  const bound = metadata(binding);
  const nonce = randomBytes(notificationPayloadEncryptionProfile.nonceBytes);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad(bound));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const bytes = Buffer.from(
    canonicalJson({
      header: bound,
      nonce: nonce.toString('hex'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('hex'),
    }),
  );
  return {
    binding,
    bytes,
    encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
    encryptionContextDigest: sha256(aad(bound)),
    encryptedObjectDigest: sha256(bytes),
  };
}

/** The caller owns the returned plaintext buffer and must erase it after its
 * bounded use. Neither successful decrypt nor possession of a historical key
 * authorizes dispatch, removes a hold or renews a revoked routing/key revision. */
export function openNotificationPayload(
  bytes: Buffer,
  expectedObjectDigest: string,
  expectedBinding: NotificationPayloadBinding,
  material: NotificationPayloadKeyMaterial,
): Buffer {
  const expected = parseBinding(expectedBinding);
  const key = exactKey(material, expected);
  let pending: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    const inspected = inspectNotificationPayload(bytes);
    if (
      !digest.safeParse(expectedObjectDigest).success ||
      inspected.encryptedObjectDigest !== expectedObjectDigest
    )
      throw new Error();
    if (canonicalJson(inspected.header) !== canonicalJson(metadata(expected))) throw new Error();
    const decipher = createDecipheriv('aes-256-gcm', key, inspected.nonce);
    decipher.setAAD(aad(inspected.header));
    decipher.setAuthTag(inspected.tag);
    pending = decipher.update(inspected.ciphertext);
    plaintext = Buffer.concat([pending, decipher.final()]);
    if (sha256(plaintext) !== expected.payloadDigest) throw new Error();
    const result = plaintext;
    plaintext = undefined;
    return result;
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  } finally {
    pending?.fill(0);
    plaintext?.fill(0);
  }
}
