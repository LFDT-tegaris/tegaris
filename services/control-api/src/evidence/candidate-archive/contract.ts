import { z } from 'zod';
import { canonicalJson, sha256 } from '../../configuration/digest.js';
import { parseStrictJsonBytes } from '../../privacy-explorer/strict-json.js';
import {
  digest,
  sequence,
  evidenceChainId,
  sourceReceipt,
  EvidenceCustodyError,
  type SourceReceipt,
} from '../segment.js';

export const CANDIDATE_CHUNK_FORMAT = 'OPENPC_CANDIDATE_PROJECTION_CHUNK_V1';
export const CANDIDATE_MANIFEST_FORMAT = 'OPENPC_CANDIDATE_PROJECTION_MANIFEST_V1';
export const CANDIDATE_PAYLOAD_LIMIT = 1_048_576;
export const CANDIDATE_CHUNK_BYTES = 65_536;
// Six base64 chunks plus bounded record/link metadata remain below the existing
// 1MiB segment plaintext cap. The manifest always occupies its own final segment.
export const CANDIDATE_CHUNKS_PER_SEGMENT = 6;
const positive = sequence.refine(
  (value) => BigInt(value) > 0n && BigInt(value) <= 9223372036854775807n,
);
export const candidateArchiveRequest = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  sourceProfileId: z.uuidv7(),
  generationId: z.uuidv7(),
  partitionId: z.uuidv7(),
  candidateId: z.uuidv7(),
});
export type CandidateArchiveRequest = z.infer<typeof candidateArchiveRequest>;
export const candidateArchiveIdentity = candidateArchiveRequest.extend({
  publicationDigest: digest,
  sourceProfileDigest: digest,
  partitionDigest: digest,
  projectionId: z.uuidv7(),
  mappingDigest: digest,
  nativeRecordId: z.string().min(1).max(256),
  recordKind: z.enum([
    'EVENT_LOG',
    'STATE_CALL',
    'TRANSACTION_RECEIPT',
    'BLOCK_HEADER',
    'FULL_BLOCK_TRANSACTIONS',
    'EXTERNAL_OBSERVATION',
  ]),
  recordSequence: sequence,
  candidateFeedSequence: positive,
  observedEventId: z.uuidv7(),
  observedEventDigest: digest,
  payloadDigest: digest,
  payloadBytes: z.number().int().min(1).max(CANDIDATE_PAYLOAD_LIMIT),
  schemaDigest: digest,
  evidenceDigest: digest,
  checkpointDigest: digest,
  occurredAt: z.iso.datetime({ precision: 6 }),
  chainId: evidenceChainId,
  genesisDigest: digest,
  block: z
    .strictObject({
      number: sequence,
      hash: digest,
      parentHash: digest,
      finalityKind: z.enum(['SAFE_TAG', 'FINALIZED_TAG', 'CONFIRMATIONS']),
      finalityEvidenceDigest: digest,
      headNumber: sequence.nullable(),
      headHash: digest.nullable(),
    })
    .refine(
      (block) =>
        (block.finalityKind === 'CONFIRMATIONS') ===
          (block.headNumber !== null && block.headHash !== null) &&
        (block.headNumber === null) === (block.headHash === null),
    ),
});
export type CandidateArchiveIdentity = z.infer<typeof candidateArchiveIdentity>;
const chunk = z.strictObject({
  index: z.number().int().min(0).max(15),
  offset: z
    .number()
    .int()
    .min(0)
    .max(CANDIDATE_PAYLOAD_LIMIT - 1),
  bytes: z.number().int().min(1).max(CANDIDATE_CHUNK_BYTES),
  recordId: z.string().regex(/^candidate:[0-9a-f]{64}:chunk:(0|[1-9][0-9]?)$/u),
  digest,
});
const manifestShape = z.strictObject({
  version: z.literal(CANDIDATE_MANIFEST_FORMAT),
  class: z.literal('CANDIDATE_PROJECTION'),
  store: z.literal('openpc_candidate_index'),
  authority: z.literal('NONE'),
  currentReadiness: z.literal('NOT_ESTABLISHED'),
  identity: candidateArchiveIdentity,
  identityDigest: digest,
  chunks: z.array(chunk).min(1).max(16),
});
export const candidateArchiveManifest = manifestShape.superRefine((manifest, ctx) => {
  const identityDigest = sha256(manifest.identity);
  if (
    manifest.identityDigest !== identityDigest ||
    manifest.chunks.length !== Math.ceil(manifest.identity.payloadBytes / CANDIDATE_CHUNK_BYTES) ||
    manifest.chunks.some(
      (item, index) =>
        item.index !== index ||
        item.offset !== index * CANDIDATE_CHUNK_BYTES ||
        item.bytes !==
          Math.min(CANDIDATE_CHUNK_BYTES, manifest.identity.payloadBytes - item.offset) ||
        item.recordId !== chunkRecordId(identityDigest, index),
    )
  )
    ctx.addIssue({ code: 'custom', message: 'Invalid exact candidate archive manifest.' });
});
export type CandidateArchiveManifest = z.infer<typeof candidateArchiveManifest>;
const prefix = (identityDigest: string) => 'candidate:' + digest.parse(identityDigest).slice(7);
export const candidateManifestRecordId = (identityDigest: string) =>
  prefix(identityDigest) + ':manifest';
const chunkRecordId = (identityDigest: string, index: number) =>
  prefix(identityDigest) + ':chunk:' + index;

const nativeSource = z.strictObject({
  version: z.literal('OPENPC_CANDIDATE_ARCHIVE_SOURCE_V1'),
  class: z.literal('CANDIDATE_PROJECTION'),
  store: z.literal('openpc_candidate_index'),
  authority: z.literal('NONE'),
  identity: candidateArchiveIdentity,
  payloadHex: z
    .string()
    .min(2)
    .max(CANDIDATE_PAYLOAD_LIMIT * 2)
    .regex(/^(?:[0-9a-f]{2})+$/u),
});
export function parseCandidateArchiveSource(
  bytes: Buffer,
  request: z.infer<typeof candidateArchiveRequest>,
) {
  if (bytes.length > 2_200_000) throw new EvidenceCustodyError('CAPACITY');
  const input = candidateArchiveRequest.parse(request);
  const value = nativeSource.parse(parseStrictJsonBytes(bytes, { maximumDepth: 8 }));
  if (
    Object.entries(input).some(
      ([key, expected]) => value.identity[key as keyof typeof input] !== expected,
    )
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const payload = Buffer.from(value.payloadHex, 'hex');
  if (
    payload.length !== value.identity.payloadBytes ||
    sha256(payload) !== value.identity.payloadDigest
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return { identity: value.identity, payload };
}

/** Internal native source result only. This function adds no signature or
 * current authority. CBOR authentication belongs to candidate_archive_reader. */
export function prepareCandidateArchive(input: CandidateArchiveIdentity, payload: Buffer) {
  const identity = candidateArchiveIdentity.parse(input),
    identityDigest = sha256(identity);
  if (
    !Buffer.isBuffer(payload) ||
    payload.length !== identity.payloadBytes ||
    sha256(payload) !== identity.payloadDigest
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const chunks: z.infer<typeof chunk>[] = [],
    records: SourceReceipt[] = [];
  for (
    let offset = 0, index = 0;
    offset < payload.length;
    offset += CANDIDATE_CHUNK_BYTES, index++
  ) {
    const bytes = payload.subarray(offset, offset + CANDIDATE_CHUNK_BYTES);
    const recordId = chunkRecordId(identityDigest, index),
      receiptDigest = sha256(bytes);
    chunks.push({ index, offset, bytes: bytes.length, recordId, digest: receiptDigest });
    records.push(
      sourceReceipt.parse({
        recordId,
        evidenceClass: 'EFFECT',
        sourceFormat: CANDIDATE_CHUNK_FORMAT,
        occurredAt: identity.occurredAt,
        receiptDigest,
        receiptBase64: bytes.toString('base64'),
      }),
    );
  }
  const manifest = candidateArchiveManifest.parse({
    version: CANDIDATE_MANIFEST_FORMAT,
    class: 'CANDIDATE_PROJECTION',
    store: 'openpc_candidate_index',
    authority: 'NONE',
    currentReadiness: 'NOT_ESTABLISHED',
    identity,
    identityDigest,
    chunks,
  });
  const bytes = Buffer.from(canonicalJson(manifest));
  const manifestRecord = sourceReceipt.parse({
    recordId: candidateManifestRecordId(identityDigest),
    evidenceClass: 'EFFECT',
    sourceFormat: CANDIDATE_MANIFEST_FORMAT,
    occurredAt: identity.occurredAt,
    receiptDigest: sha256(bytes),
    receiptBase64: bytes.toString('base64'),
  });
  const batches: SourceReceipt[][] = [];
  for (let index = 0; index < records.length; index += CANDIDATE_CHUNKS_PER_SEGMENT)
    batches.push(records.slice(index, index + CANDIDATE_CHUNKS_PER_SEGMENT));
  batches.push([manifestRecord]);
  return { manifest, manifestRecord, batches };
}
export type PreparedCandidateArchive = ReturnType<typeof prepareCandidateArchive>;

/** Exact ordered original custody only: no latest aliases or regenerated data. */
export function reconstructCandidateArchive(
  input: CandidateArchiveManifest,
  records: readonly SourceReceipt[],
) {
  const manifest = candidateArchiveManifest.parse(input);
  if (records.length !== manifest.chunks.length + 1) throw new EvidenceCustodyError('INTEGRITY');
  const chunks = manifest.chunks.map((item, index) => {
    const record = sourceReceipt.parse(records[index]),
      bytes = Buffer.from(record.receiptBase64, 'base64');
    if (
      record.recordId !== item.recordId ||
      record.sourceFormat !== CANDIDATE_CHUNK_FORMAT ||
      record.evidenceClass !== 'EFFECT' ||
      record.occurredAt !== manifest.identity.occurredAt ||
      bytes.toString('base64') !== record.receiptBase64 ||
      bytes.length !== item.bytes ||
      record.receiptDigest !== item.digest ||
      sha256(bytes) !== item.digest
    )
      throw new EvidenceCustodyError('INTEGRITY');
    return bytes;
  });
  const original = sourceReceipt.parse(records[records.length - 1]);
  const manifestBytes = Buffer.from(canonicalJson(manifest));
  if (
    original.recordId !== candidateManifestRecordId(manifest.identityDigest) ||
    original.sourceFormat !== CANDIDATE_MANIFEST_FORMAT ||
    original.evidenceClass !== 'EFFECT' ||
    original.occurredAt !== manifest.identity.occurredAt ||
    original.receiptDigest !== sha256(manifestBytes) ||
    original.receiptBase64 !== manifestBytes.toString('base64')
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const payload = Buffer.concat(chunks);
  if (
    payload.length !== manifest.identity.payloadBytes ||
    sha256(payload) !== manifest.identity.payloadDigest
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return payload;
}
