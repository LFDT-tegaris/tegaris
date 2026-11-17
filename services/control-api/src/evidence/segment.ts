import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';

export class EvidenceCustodyError extends Error {
  constructor(
    readonly code: 'INVALID' | 'CONFLICT' | 'UNAVAILABLE' | 'CAPACITY' | 'INTEGRITY' | 'HELD',
  ) {
    super(`Evidence custody ${code.toLowerCase()}`);
  }
}

export const evidenceChainId = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,77})$/u, { abort: true })
  .refine((value) => BigInt(value) < 2n ** 256n);
export const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const sequence = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u, { abort: true })
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const reference = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
export const evidenceScope = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  streamId: reference,
});
export type EvidenceScope = z.infer<typeof evidenceScope>;
export const evidenceClass = z.enum(['AUTHENTICATION', 'BUSINESS_TRANSITION', 'EFFECT']);

// Source adapters supply retained receipt bytes, never request/provider payloads.
// A source receipt is not reinterpreted as a different class or as authority.
export const sourceReceipt = z.strictObject({
  recordId: reference,
  evidenceClass,
  sourceFormat: reference,
  occurredAt: z.iso.datetime({ precision: 6 }),
  receiptDigest: digest,
  receiptBase64: z.string().max(180_000),
});
export type SourceReceipt = z.infer<typeof sourceReceipt>;

const headerSchema = evidenceScope.extend({
  version: z.literal('OPENPC_EVIDENCE_SEGMENT_V1'),
  segmentId: z.uuid(),
  firstSequence: sequence,
  throughSequence: sequence,
  previousSegmentDigest: digest.nullable(),
  keyId: reference,
  retentionUntil: z.iso.datetime({ precision: 6 }),
});
export type SegmentHeader = z.infer<typeof headerSchema>;
const envelopeSchema = z.strictObject({
  header: headerSchema,
  nonce: z.string().regex(/^[0-9a-f]{24}$/u),
  ciphertext: z.string().max(2_000_000),
  tag: z.string().regex(/^[0-9a-f]{32}$/u),
});
const recordSchema = sourceReceipt.extend({
  sequence,
  previousRecordDigest: digest.nullable(),
  recordDigest: digest,
});
const payloadSchema = z.strictObject({
  records: z.array(recordSchema).min(1).max(128),
  footer: z.strictObject({ count: z.number().int().min(1).max(128), lastRecordDigest: digest }),
});
export const MAX_SEGMENT_BYTES = 2 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 1024 * 1024;

function decodeBase64(value: string): Buffer {
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length === 0)
    throw new EvidenceCustodyError('INVALID');
  return bytes;
}
function receipt(value: SourceReceipt): SourceReceipt {
  const parsed = sourceReceipt.parse(value);
  if (sha256(decodeBase64(parsed.receiptBase64)) !== parsed.receiptDigest)
    throw new EvidenceCustodyError('INTEGRITY');
  return parsed;
}
function header(value: SegmentHeader): SegmentHeader {
  const parsed = headerSchema.parse(value);
  if (
    BigInt(parsed.firstSequence) === 0n ||
    BigInt(parsed.throughSequence) < BigInt(parsed.firstSequence) ||
    BigInt(parsed.throughSequence) - BigInt(parsed.firstSequence) >= 128n ||
    (parsed.firstSequence === '1') !== (parsed.previousSegmentDigest === null)
  )
    throw new EvidenceCustodyError('INVALID');
  return parsed;
}

/** Structural inspection is not decryption, receipt authentication, or durable admission. */
export function inspectSegment(bytes: Buffer) {
  if (bytes.length > MAX_SEGMENT_BYTES) throw new EvidenceCustodyError('CAPACITY');
  try {
    const envelope = envelopeSchema.parse(JSON.parse(bytes.toString('utf8')));
    if (canonicalJson(envelope) !== bytes.toString('utf8'))
      throw new EvidenceCustodyError('INTEGRITY');
    decodeBase64(envelope.ciphertext);
    return { header: header(envelope.header), objectDigest: sha256(bytes) };
  } catch (error) {
    if (error instanceof EvidenceCustodyError) throw error;
    throw new EvidenceCustodyError('INTEGRITY');
  }
}

/** An immutable encrypted segment; original COSE receipts retain their own signature domains. */
export function sealSegment(input: SegmentHeader, records: readonly SourceReceipt[], key: Buffer) {
  const metadata = header(input);
  if (
    key.length !== 32 ||
    records.length !==
      Number(BigInt(metadata.throughSequence) - BigInt(metadata.firstSequence) + 1n)
  )
    throw new EvidenceCustodyError('INVALID');
  const ids = new Set<string>();
  let previousRecordDigest: string | null = metadata.previousSegmentDigest;
  const linked = records.map((value, index) => {
    const source = receipt(value);
    if (ids.has(source.recordId)) throw new EvidenceCustodyError('CONFLICT');
    ids.add(source.recordId);
    const record = {
      ...source,
      sequence: String(BigInt(metadata.firstSequence) + BigInt(index)),
      previousRecordDigest,
    };
    const recordDigest = sha256(record);
    previousRecordDigest = recordDigest;
    return { ...record, recordDigest };
  });
  const plaintext = Buffer.from(
    canonicalJson({
      records: linked,
      footer: { count: linked.length, lastRecordDigest: previousRecordDigest },
    }),
  );
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new EvidenceCustodyError('CAPACITY');
  try {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(canonicalJson(metadata)));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const bytes = Buffer.from(
      canonicalJson({
        header: metadata,
        nonce: nonce.toString('hex'),
        ciphertext: ciphertext.toString('base64'),
        tag: cipher.getAuthTag().toString('hex'),
      }),
    );
    if (bytes.length > MAX_SEGMENT_BYTES) throw new EvidenceCustodyError('CAPACITY');
    return { header: metadata, bytes, objectDigest: sha256(bytes) };
  } finally {
    plaintext.fill(0);
  }
}

/** Verify against the caller's retained exact identity, never a mutable latest alias. */
export function openSegment(
  bytes: Buffer,
  expectedDigest: string,
  expectedHeader: SegmentHeader,
  key: Buffer,
) {
  if (bytes.length > MAX_SEGMENT_BYTES || key.length !== 32 || sha256(bytes) !== expectedDigest)
    throw new EvidenceCustodyError('INTEGRITY');
  let plaintext: Buffer | undefined;
  try {
    const envelope = envelopeSchema.parse(JSON.parse(bytes.toString('utf8')));
    const metadata = header(envelope.header);
    if (canonicalJson(metadata) !== canonicalJson(header(expectedHeader)))
      throw new EvidenceCustodyError('INTEGRITY');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'hex'));
    decipher.setAAD(Buffer.from(canonicalJson(metadata)));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
    plaintext = Buffer.concat([
      decipher.update(decodeBase64(envelope.ciphertext)),
      decipher.final(),
    ]);
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new EvidenceCustodyError('CAPACITY');
    const payload = payloadSchema.parse(JSON.parse(plaintext.toString('utf8')));
    if (
      payload.records.length !==
        Number(BigInt(metadata.throughSequence) - BigInt(metadata.firstSequence) + 1n) ||
      payload.footer.count !== payload.records.length
    )
      throw new EvidenceCustodyError('INTEGRITY');
    let previous: string | null = metadata.previousSegmentDigest;
    const ids = new Set<string>();
    payload.records.forEach(({ recordDigest, ...record }, index) => {
      const { sequence: ordinal, previousRecordDigest, ...source } = record;
      receipt(source);
      if (
        ordinal !== String(BigInt(metadata.firstSequence) + BigInt(index)) ||
        previousRecordDigest !== previous ||
        sha256(record) !== recordDigest ||
        ids.has(record.recordId)
      )
        throw new EvidenceCustodyError('INTEGRITY');
      previous = recordDigest;
      ids.add(record.recordId);
    });
    if (payload.footer.lastRecordDigest !== previous) throw new EvidenceCustodyError('INTEGRITY');
    return { header: metadata, records: payload.records, footer: payload.footer };
  } catch (error) {
    if (error instanceof EvidenceCustodyError) throw error;
    throw new EvidenceCustodyError('INTEGRITY');
  } finally {
    plaintext?.fill(0);
  }
}
