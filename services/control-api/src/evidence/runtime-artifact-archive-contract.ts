import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { parseStrictJsonBytes } from '../privacy-explorer/strict-json.js';
import { digest, EvidenceCustodyError, sourceReceipt, type SourceReceipt } from './segment.js';

export const RUNTIME_ARTIFACT_CHUNK_FORMAT = 'OPENPC_RUNTIME_ARTIFACT_CHUNK_V1';
export const RUNTIME_ARTIFACT_MANIFEST_FORMAT = 'OPENPC_RUNTIME_ARTIFACT_MANIFEST_V1';
export const RUNTIME_ARTIFACT_MAX_BYTES = 4_194_304;
export const RUNTIME_ARTIFACT_CHUNK_BYTES = 65_536;
// Each group fits the existing segment plaintext bound; the manifest follows
// in its own segment. No new vault, cipher, archive transport or receipt class.
export const RUNTIME_ARTIFACT_CHUNKS_PER_SEGMENT = 6;

export const runtimeArtifactArchiveIdentity = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  runtimeConfigurationInputId: z.uuidv7(),
  moduleInstallationId: z.uuidv7(),
  moduleConfigurationGenerationId: z.uuidv7(),
  configurationDigest: digest,
  configurationBytes: z.number().int().min(1).max(RUNTIME_ARTIFACT_MAX_BYTES),
  resourceBindingsDigest: digest,
  createdAt: z.iso.datetime({ precision: 6 }),
});
export type RuntimeArtifactArchiveIdentity = z.infer<typeof runtimeArtifactArchiveIdentity>;
const identityDigest = (identity: RuntimeArtifactArchiveIdentity) =>
  sha256({ domain: 'pc.runtime-artifact.archive-identity.v1', identity });
const prefix = (value: string) => `runtime-artifact:${digest.parse(value).slice(7)}`;
const chunkRecordId = (value: string, index: number) => `${prefix(value)}:chunk:${index}`;
export const runtimeArtifactManifestRecordId = (value: string) => `${prefix(value)}:manifest`;

const chunk = z.strictObject({
  index: z.number().int().min(0).max(63),
  offset: z
    .number()
    .int()
    .min(0)
    .max(RUNTIME_ARTIFACT_MAX_BYTES - 1),
  bytes: z.number().int().min(1).max(RUNTIME_ARTIFACT_CHUNK_BYTES),
  recordId: z.string().regex(/^runtime-artifact:[0-9a-f]{64}:chunk:(0|[1-9][0-9]?)$/u),
  digest,
});
export const runtimeArtifactArchiveManifest = z
  .strictObject({
    version: z.literal(RUNTIME_ARTIFACT_MANIFEST_FORMAT),
    class: z.literal('RUNTIME_ARTIFACT'),
    store: z.literal('openpc_control'),
    authority: z.literal('NONE'),
    currentReadiness: z.literal('NOT_ESTABLISHED'),
    identity: runtimeArtifactArchiveIdentity,
    identityDigest: digest,
    chunks: z.array(chunk).min(1).max(64),
  })
  .superRefine((manifest, context) => {
    if (
      manifest.identityDigest !== identityDigest(manifest.identity) ||
      manifest.chunks.length !==
        Math.ceil(manifest.identity.configurationBytes / RUNTIME_ARTIFACT_CHUNK_BYTES) ||
      manifest.chunks.some(
        (item, index) =>
          item.index !== index ||
          item.offset !== index * RUNTIME_ARTIFACT_CHUNK_BYTES ||
          item.bytes !==
            Math.min(
              RUNTIME_ARTIFACT_CHUNK_BYTES,
              manifest.identity.configurationBytes - item.offset,
            ) ||
          item.recordId !== chunkRecordId(manifest.identityDigest, index),
      )
    )
      context.addIssue({ code: 'custom', message: 'Invalid exact runtime artifact manifest.' });
  });
export type RuntimeArtifactArchiveManifest = z.infer<typeof runtimeArtifactArchiveManifest>;

/** Packaging only. The native database source and custody admission must verify
 * the original row; supplied metadata, manifest or bytes confer no authority.
 * These records are not signed receipts and must not enter a public receipt
 * export without an explicit class-specific field-filtering owner. */
export function prepareRuntimeArtifactArchive(
  input: RuntimeArtifactArchiveIdentity,
  payload: Buffer,
) {
  const identity = runtimeArtifactArchiveIdentity.parse(input);
  if (
    !Buffer.isBuffer(payload) ||
    payload.length !== identity.configurationBytes ||
    sha256(payload) !== identity.configurationDigest
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const bound = identityDigest(identity);
  const chunks: z.infer<typeof chunk>[] = [];
  const records: SourceReceipt[] = [];
  for (
    let offset = 0, index = 0;
    offset < payload.length;
    offset += RUNTIME_ARTIFACT_CHUNK_BYTES, index++
  ) {
    const bytes = payload.subarray(offset, offset + RUNTIME_ARTIFACT_CHUNK_BYTES);
    const recordId = chunkRecordId(bound, index),
      receiptDigest = sha256(bytes);
    chunks.push({ index, offset, bytes: bytes.length, recordId, digest: receiptDigest });
    records.push(
      sourceReceipt.parse({
        recordId,
        evidenceClass: 'EFFECT',
        sourceFormat: RUNTIME_ARTIFACT_CHUNK_FORMAT,
        occurredAt: identity.createdAt,
        receiptDigest,
        receiptBase64: bytes.toString('base64'),
      }),
    );
  }
  const manifest = runtimeArtifactArchiveManifest.parse({
    version: RUNTIME_ARTIFACT_MANIFEST_FORMAT,
    class: 'RUNTIME_ARTIFACT',
    store: 'openpc_control',
    authority: 'NONE',
    currentReadiness: 'NOT_ESTABLISHED',
    identity,
    identityDigest: bound,
    chunks,
  });
  const bytes = Buffer.from(canonicalJson(manifest));
  const manifestRecord = sourceReceipt.parse({
    recordId: runtimeArtifactManifestRecordId(bound),
    evidenceClass: 'EFFECT',
    sourceFormat: RUNTIME_ARTIFACT_MANIFEST_FORMAT,
    occurredAt: identity.createdAt,
    receiptDigest: sha256(bytes),
    receiptBase64: bytes.toString('base64'),
  });
  const groups: SourceReceipt[][] = [];
  for (let index = 0; index < records.length; index += RUNTIME_ARTIFACT_CHUNKS_PER_SEGMENT)
    groups.push(records.slice(index, index + RUNTIME_ARTIFACT_CHUNKS_PER_SEGMENT));
  groups.push([manifestRecord]);
  return { manifest, groups };
}

/** Validate exact original identity, every chunk and complete bytes on readback.
 * Even a successful reconstruction is neither retention clearance nor permission
 * to reselect, restore or serve the artifact. No partial result is returned. */
export function reconstructRuntimeArtifactArchive(
  expectedInput: RuntimeArtifactArchiveIdentity,
  input: readonly SourceReceipt[],
) {
  const expected = runtimeArtifactArchiveIdentity.parse(expectedInput);
  if (input.length < 2 || input.length > 65) throw new EvidenceCustodyError('INTEGRITY');
  const records = input.map((value) => sourceReceipt.parse(value));
  const last = records.at(-1)!;
  const decode = (record: SourceReceipt, limit: number) => {
    const bytes = Buffer.from(record.receiptBase64, 'base64');
    if (
      bytes.length === 0 ||
      bytes.length > limit ||
      bytes.toString('base64') !== record.receiptBase64 ||
      sha256(bytes) !== record.receiptDigest
    )
      throw new EvidenceCustodyError('INTEGRITY');
    return bytes;
  };
  const manifestBytes = decode(last, 32_768);
  const manifest = runtimeArtifactArchiveManifest.parse(
    parseStrictJsonBytes(manifestBytes, { maximumDepth: 8 }),
  );
  if (
    last.sourceFormat !== RUNTIME_ARTIFACT_MANIFEST_FORMAT ||
    last.recordId !== runtimeArtifactManifestRecordId(identityDigest(expected)) ||
    last.evidenceClass !== 'EFFECT' ||
    last.occurredAt !== expected.createdAt ||
    canonicalJson(manifest) !== manifestBytes.toString('utf8') ||
    canonicalJson(manifest.identity) !== canonicalJson(expected) ||
    records.length !== manifest.chunks.length + 1
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const payload = Buffer.alloc(expected.configurationBytes);
  try {
    for (const item of manifest.chunks) {
      const record = records[item.index]!;
      if (
        record.recordId !== item.recordId ||
        record.sourceFormat !== RUNTIME_ARTIFACT_CHUNK_FORMAT ||
        record.evidenceClass !== 'EFFECT' ||
        record.occurredAt !== expected.createdAt ||
        record.receiptDigest !== item.digest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const bytes = decode(record, RUNTIME_ARTIFACT_CHUNK_BYTES);
      if (bytes.length !== item.bytes) throw new EvidenceCustodyError('INTEGRITY');
      bytes.copy(payload, item.offset);
    }
    if (sha256(payload) !== expected.configurationDigest)
      throw new EvidenceCustodyError('INTEGRITY');
    return { manifest, payload };
  } catch (error) {
    payload.fill(0);
    throw error;
  }
}
