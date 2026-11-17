import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { evidenceExportCoseContext } from './generated.js';

export const evidenceExportCompletedType = 'io.openpc.evidence.export.completed.v1';
export const evidenceExportCompletedSchema =
  'https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted';
export const evidenceExportCompletionNamespace = 'EVIDENCE_EXPORT_COMPLETION_V1';

export interface EvidenceExportCompletionClaims {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  eventId: string;
  sourceId: string;
  evidenceExportId: string;
  startOperationId: string;
  causationId: string;
  sequence: string;
  recordedAtNs: string;
  requestDigest: string;
  checkpoint: string;
  outputDigest: string;
  recordCount: string;
  dataDigest: string;
  authoritySnapshotDigest: string;
  signerTrustSnapshotDigest: string;
  signerKeyId: string;
}
type CompletionData = Pick<
  EvidenceExportCompletionClaims,
  'evidenceExportId' | 'checkpoint' | 'outputDigest' | 'recordCount'
>;
const reject = (): never => {
  throw new Error('Invalid evidence export completion');
};
const hash = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function uuid(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value) ||
    value.length !== 36
  )
    return reject();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function h32(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value) || value.length !== 71)
    return reject();
  return Buffer.from(value.slice(7), 'hex');
}
function positive(value: unknown): bigint {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(value) || value !== value.trim())
    return reject();
  const result = BigInt(value);
  if (result > MAX_UINT64) return reject();
  return result;
}
function keyId(value: unknown): string {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value) || value.length !== 71)
    return reject();
  return value;
}
function field(type: string, value: unknown): CborValue {
  if (type === 'uuidv7') return uuid(value);
  if (type === 'H32') return h32(value);
  if (type === 'u64p') return positive(value);
  if (type === 'keyId') return keyId(value);
  if (
    type === 'text160' &&
    typeof value === 'string' &&
    /^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u.test(value) &&
    value === value.trim()
  )
    return value;
  return reject();
}

/** Exact registered event DATA preimage. This codec grants no source authority. */
export function encodeEvidenceExportCompletedData(value: CompletionData): Buffer {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== 4 ||
    Object.keys(value).some(
      (key) => !['evidenceExportId', 'checkpoint', 'outputDigest', 'recordCount'].includes(key),
    )
  )
    return reject();
  uuid(value.evidenceExportId);
  const recordCount = positive(value.recordCount);
  if (recordCount > 128n || recordCount > positive(value.checkpoint)) return reject();
  return encodeCbor(
    new Map<number, CborValue>([
      [0, `urn:openpc:resource:${value.evidenceExportId}`],
      [1, positive(value.checkpoint)],
      [2, h32(value.outputDigest)],
      [3, recordCount],
    ]),
  );
}

/** Closed signed metadata; current workload/key/source admission is separate. */
export function encodeEvidenceExportCompletion(value: EvidenceExportCompletionClaims): Buffer {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return reject();
  const fields = evidenceExportCoseContext.fields;
  const keys = Object.keys(value);
  if (
    keys.length !== fields.length - 1 ||
    keys.some((key) => !fields.some((item) => item.key !== 0 && item.name === key))
  )
    return reject();
  const values = value as unknown as Record<string, unknown>;
  const wire = new Map<number, CborValue>();
  for (const item of fields)
    wire.set(
      item.key,
      field(
        item.type,
        item.key === 0 ? evidenceExportCoseContext.definitionDigest : values[item.name],
      ),
    );
  const ns = positive(value.recordedAtNs);
  const { evidenceExportId, checkpoint, outputDigest, recordCount } = value;
  if (
    ns % 1000n !== 0n ||
    hash(
      encodeEvidenceExportCompletedData({
        evidenceExportId,
        checkpoint,
        outputDigest,
        recordCount,
      }),
    ) !== value.dataDigest
  )
    return reject();
  return encodeCbor(wire);
}

export function decodeEvidenceExportCompletion(bytes: Buffer): EvidenceExportCompletionClaims {
  const wire = decodeCbor(bytes);
  if (!(wire instanceof Map) || wire.size !== evidenceExportCoseContext.fields.length)
    return reject();
  if (
    !Buffer.isBuffer(wire.get(0)) ||
    !(wire.get(0) as Buffer).equals(h32(evidenceExportCoseContext.definitionDigest))
  )
    return reject();
  const value: Record<string, unknown> = {};
  for (const item of evidenceExportCoseContext.fields) {
    if (item.key === 0) continue;
    const raw = wire.get(item.key);
    if (item.type === 'uuidv7') {
      if (!Buffer.isBuffer(raw) || raw.length !== 16) return reject();
      const hex = raw.toString('hex');
      value[item.name] =
        `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    } else if (item.type === 'H32') {
      if (!Buffer.isBuffer(raw) || raw.length !== 32) return reject();
      value[item.name] = `sha256:${raw.toString('hex')}`;
    } else if (item.type === 'u64p') {
      if (typeof raw !== 'number' && typeof raw !== 'bigint') return reject();
      value[item.name] = String(raw);
    } else value[item.name] = raw;
  }
  const claims = value as unknown as EvidenceExportCompletionClaims;
  if (!encodeEvidenceExportCompletion(claims).equals(bytes)) return reject();
  return claims;
}

/** Exact public projection, including full URNs and microsecond precision. */
export function evidenceExportCompletionEnvelope(value: EvidenceExportCompletionClaims) {
  encodeEvidenceExportCompletion(value);
  const ns = BigInt(value.recordedAtNs);
  const date = new Date(Number(ns / 1_000_000n)).toISOString();
  return {
    specversion: '1.0' as const,
    id: value.eventId,
    source: `urn:openpc:service:${value.sourceId}`,
    type: evidenceExportCompletedType,
    subject: `urn:openpc:resource:${value.evidenceExportId}`,
    time: `${date.slice(0, 19)}.${((ns / 1000n) % 1_000_000n).toString().padStart(6, '0')}Z`,
    datacontenttype: 'application/json' as const,
    dataschema: evidenceExportCompletedSchema,
    participantid: `urn:openpc:participant:${value.participantId}`,
    privacydomainid: `urn:openpc:privacy-domain:${value.privacyDomainId}`,
    correlationid: value.startOperationId,
    causationid: value.causationId,
    sequence: value.sequence,
    datadigest: value.dataDigest,
    data: {
      evidenceExportId: `urn:openpc:resource:${value.evidenceExportId}`,
      checkpoint: value.checkpoint,
      outputDigest: value.outputDigest,
      recordCount: value.recordCount,
    },
  };
}

export function signEvidenceExportCompletion(
  value: EvidenceExportCompletionClaims,
  privateKey: Buffer,
  spki: Buffer,
): Buffer {
  if (value.signerKeyId !== evidenceKeyId(spki)) return reject();
  return signConsumerCose(
    evidenceExportCoseContext,
    privateKey,
    spki,
    encodeEvidenceExportCompletion(value),
  );
}
export function verifyEvidenceExportCompletion(
  value: EvidenceExportCompletionClaims,
  spki: Buffer,
  cose: Buffer,
): boolean {
  try {
    return (
      value.signerKeyId === evidenceKeyId(spki) &&
      verifyConsumerCose(
        evidenceExportCoseContext,
        spki,
        encodeEvidenceExportCompletion(value),
        cose,
      )
    );
  } catch {
    return false;
  }
}
