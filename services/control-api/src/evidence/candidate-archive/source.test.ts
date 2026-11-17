import { candidateRetirementSelection } from './retirement-selection.js';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../../configuration/digest.js';
import { openSegment, sealSegment, type SegmentHeader, type SourceReceipt } from '../segment.js';
import {
  CANDIDATE_PAYLOAD_LIMIT,
  candidateArchiveIdentity,
  candidateArchiveManifest,
  parseCandidateArchiveSource,
  prepareCandidateArchive,
  reconstructCandidateArchive,
} from './contract.js';

const id = (last: number) => '018f0000-0000-7000-8000-' + String(last).padStart(12, '0');
const hash = 'sha256:' + 'a'.repeat(64);
function source(payload: Buffer) {
  return candidateArchiveIdentity.parse({
    participantId: id(1),
    privacyDomainId: id(2),
    sourceProfileId: id(3),
    generationId: id(4),
    partitionId: id(5),
    candidateId: id(6),
    publicationDigest: hash,
    sourceProfileDigest: hash,
    partitionDigest: hash,
    projectionId: id(7),
    mappingDigest: hash,
    nativeRecordId: 'native-record-1',
    recordKind: 'STATE_CALL',
    recordSequence: '1',
    candidateFeedSequence: '9007199254740993',
    observedEventId: id(8),
    observedEventDigest: hash,
    payloadDigest: sha256(payload),
    payloadBytes: payload.length,
    schemaDigest: hash,
    evidenceDigest: hash,
    checkpointDigest: hash,
    occurredAt: '2026-09-24T00:00:00.000001Z',
    chainId: '31337',
    genesisDigest: hash,
    block: {
      number: '3',
      hash,
      parentHash: hash,
      finalityKind: 'FINALIZED_TAG',
      finalityEvidenceDigest: hash,
      headNumber: null,
      headHash: null,
    },
  });
}
const request = () => ({
  participantId: id(1),
  privacyDomainId: id(2),
  sourceProfileId: id(3),
  generationId: id(4),
  partitionId: id(5),
  candidateId: id(6),
});
function maximumPayload() {
  const bytes = Buffer.alloc(CANDIDATE_PAYLOAD_LIMIT, 0x42);
  Buffer.from([0x5a, 0x00, 0x0f, 0xff, 0xfb]).copy(bytes);
  return bytes;
}

describe('candidate archive original bytes and complete manifest', () => {
  it('preserves a full 1MiB native CBOR payload across actual bounded encrypted segments', () => {
    const payload = maximumPayload(),
      identity = source(payload);
    const prepared = prepareCandidateArchive(identity, payload),
      key = Buffer.alloc(32, 3);
    expect(prepared.batches.map((batch) => batch.length)).toEqual([6, 6, 4, 1]);
    const records: SourceReceipt[] = [],
      headers: SegmentHeader[] = [];
    let sequence = 1n,
      previous: string | null = null;
    for (const batch of prepared.batches) {
      expect(batch.every((record) => record.receiptBase64.length <= 180_000)).toBe(true);
      const header: SegmentHeader = {
        version: 'OPENPC_EVIDENCE_SEGMENT_V1',
        participantId: identity.participantId,
        privacyDomainId: identity.privacyDomainId,
        streamId: 'candidate-unit',
        segmentId: randomUUID(),
        firstSequence: String(sequence),
        throughSequence: String(sequence + BigInt(batch.length) - 1n),
        previousSegmentDigest: previous,
        keyId: 'candidate-unit-key',
        retentionUntil: '2026-09-25T00:00:00.000000Z',
      };
      const sealed = sealSegment(header, batch, key);
      // The actual shared encoder enforces both plaintext and ciphertext limits.
      expect(sealed.bytes.length).toBeLessThanOrEqual(2 * 1024 * 1024);
      const opened = openSegment(sealed.bytes, sealed.objectDigest, header, key);
      records.push(
        ...opened.records.map((record) => ({
          recordId: record.recordId,
          evidenceClass: record.evidenceClass,
          sourceFormat: record.sourceFormat,
          occurredAt: record.occurredAt,
          receiptDigest: record.receiptDigest,
          receiptBase64: record.receiptBase64,
        })),
      );
      headers.push(header);
      previous = sealed.objectDigest;
      sequence += BigInt(batch.length);
      expect(() =>
        openSegment(sealed.bytes, sealed.objectDigest, header, Buffer.alloc(32, 9)),
      ).toThrow();
    }
    expect(headers.length).toBe(4);
    expect(reconstructCandidateArchive(prepared.manifest, records)).toEqual(payload);
    expect(prepareCandidateArchive(identity, payload)).toEqual(prepared);
    expect(prepared.manifest.authority).toBe('NONE');
    expect(prepared.manifest.currentReadiness).toBe('NOT_ESTABLISHED');
  }, 20_000);

  it('rejects altered bytes, size, identity, chunk order/offset/count and missing or substituted records', () => {
    const payload = maximumPayload(),
      identity = source(payload),
      prepared = prepareCandidateArchive(identity, payload);
    const original = prepared.batches.flat();
    const modified = Buffer.from(payload);
    modified[20] = modified[20]! ^ 1;
    expect(() => prepareCandidateArchive(identity, modified)).toThrow();
    expect(() => prepareCandidateArchive({ ...identity, payloadBytes: 1 }, payload)).toThrow();
    expect(() =>
      prepareCandidateArchive(
        source(Buffer.alloc(CANDIDATE_PAYLOAD_LIMIT)),
        Buffer.alloc(CANDIDATE_PAYLOAD_LIMIT + 1),
      ),
    ).toThrow();
    for (const records of [
      original.slice(1),
      original.slice(0, -1),
      [...original, original[0]!],
      [original[1]!, original[0]!, ...original.slice(2)],
      original.map((record, index) =>
        index === 0 ? { ...record, receiptBase64: 'AQ==' } : record,
      ),
      original.map((record, index) =>
        index === 0 ? { ...record, recordId: original[1]!.recordId } : record,
      ),
      original.map((record) => ({ ...record, occurredAt: '2026-09-24T00:00:00.000002Z' })),
    ])
      expect(() => reconstructCandidateArchive(prepared.manifest, records)).toThrow();
    for (const changed of [
      { ...prepared.manifest, identity: { ...identity, participantId: id(99) } },
      { ...prepared.manifest, chunks: prepared.manifest.chunks.slice(1) },
      {
        ...prepared.manifest,
        chunks: prepared.manifest.chunks.map((chunk, index) =>
          index === 0 ? { ...chunk, offset: 1 } : chunk,
        ),
      },
      { ...prepared.manifest, chunks: [...prepared.manifest.chunks].reverse() },
      { ...prepared.manifest, authority: 'SIGNED_FACT' },
    ])
      expect(candidateArchiveManifest.safeParse(changed).success).toBe(false);
    expect(() =>
      reconstructCandidateArchive(
        prepared.manifest,
        original.map((record) =>
          record === original.at(-1)
            ? { ...record, receiptBase64: Buffer.from('{}').toString('base64') }
            : record,
        ),
      ),
    ).toThrow();
  });

  it('binds native output to every requested identity without numeric sequence coercion', () => {
    const payload = Buffer.from([0xa0]),
      identity = source(payload);
    const body = {
      version: 'OPENPC_CANDIDATE_ARCHIVE_SOURCE_V1',
      class: 'CANDIDATE_PROJECTION',
      store: 'openpc_candidate_index',
      authority: 'NONE',
      identity,
      payloadHex: payload.toString('hex'),
    };
    const bytes = Buffer.from(JSON.stringify(body));
    expect(parseCandidateArchiveSource(bytes, request()).identity.candidateFeedSequence).toBe(
      '9007199254740993',
    );
    for (const key of Object.keys(request()))
      expect(() => parseCandidateArchiveSource(bytes, { ...request(), [key]: id(99) })).toThrow();
    expect(() =>
      parseCandidateArchiveSource(
        Buffer.from(JSON.stringify({ ...body, eligible: true })),
        request(),
      ),
    ).toThrow();
    expect(() =>
      parseCandidateArchiveSource(
        Buffer.from(JSON.stringify({ ...body, payloadHex: 'a1' })),
        request(),
      ),
    ).toThrow();
    expect(() =>
      parseCandidateArchiveSource(
        Buffer.from('{"authority":"NONE",' + JSON.stringify(body).slice(1)),
        request(),
      ),
    ).toThrow();
  });

  it('keeps feed gaps separate from archive sequence and binds identical payloads to distinct sources', () => {
    const payload = Buffer.from([0xa0]),
      identity = source(payload);
    const first = prepareCandidateArchive(identity, payload);
    const second = prepareCandidateArchive(
      { ...identity, candidateId: id(90), candidateFeedSequence: '9007199254740995' },
      payload,
    );
    expect(first.manifest.chunks[0]!.digest).toBe(second.manifest.chunks[0]!.digest);
    expect(first.manifest.chunks[0]!.recordId).not.toBe(second.manifest.chunks[0]!.recordId);
    expect(first.manifestRecord.receiptDigest).toBe(
      sha256(Buffer.from(canonicalJson(first.manifest))),
    );
  });
});

it('derives a historical candidate selection with exact large ordinals and rejects tampered manifest identity', () => {
  const payload = maximumPayload();
  const { manifest } = prepareCandidateArchive(source(payload), payload);
  const selected = candidateRetirementSelection(manifest);
  expect(selected.class).toBe('CANDIDATE_PROJECTION');
  expect(selected.source).toEqual({
    profile_id: id(3),
    generation_id: id(4),
    partition_id: id(5),
    identity_digest: hash.slice(7),
  });
  expect(selected.rows).toEqual([
    {
      candidate_id: id(6),
      candidate_feed_sequence: 9007199254740993n,
      payload_digest: sha256(payload).slice(7),
      payload_bytes: 1048576n,
      checkpoint_digest: hash.slice(7),
    },
  ]);
  for (const field of ['candidateId', 'generationId', 'partitionId', 'sourceProfileId'])
    expect(() =>
      candidateRetirementSelection({
        ...manifest,
        identity: { ...manifest.identity, [field]: id(99) },
      }),
    ).toThrow();
  expect(() => candidateRetirementSelection({ ...manifest, authority: 'EXECUTE' })).toThrow();
  expect(() =>
    candidateRetirementSelection({ ...manifest, chunks: manifest.chunks.slice(1) }),
  ).toThrow();
});
