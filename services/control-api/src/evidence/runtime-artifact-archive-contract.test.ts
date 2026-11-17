import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { Pool } from 'pg';
import { z } from 'zod';
import { readRuntimeArtifactArchiveSource } from './runtime-artifact-archive-source.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { openSegment, sealSegment, type SourceReceipt } from './segment.js';
import {
  prepareRuntimeArtifactArchive,
  reconstructRuntimeArtifactArchive,
  RUNTIME_ARTIFACT_MAX_BYTES,
  runtimeArtifactArchiveManifest,
} from './runtime-artifact-archive-contract.js';

const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const identity = (bytes: Buffer) => ({
  participantId: id(1),
  privacyDomainId: id(2),
  runtimeConfigurationInputId: id(3),
  moduleInstallationId: id(4),
  moduleConfigurationGenerationId: id(5),
  configurationDigest: sha256(bytes),
  configurationBytes: bytes.length,
  resourceBindingsDigest: sha256({ bindings: ['native-owner'] }),
  createdAt: '2026-09-25T12:00:00.123456Z',
});

it.each([1, 65_536, 65_537, RUNTIME_ARTIFACT_MAX_BYTES])(
  'round trips all %i original bytes through existing encrypted segments without granting readiness',
  (size) => {
    const payload = randomBytes(size),
      source = identity(payload);
    const prepared = prepareRuntimeArtifactArchive(source, payload);
    const key = randomBytes(32),
      restored: SourceReceipt[] = [];
    let previous: string | null = null,
      sequence = 1;
    for (const [index, group] of prepared.groups.entries()) {
      const sealed = sealSegment(
        {
          participantId: source.participantId,
          privacyDomainId: source.privacyDomainId,
          streamId: 'runtime-artifact-test',
          version: 'OPENPC_EVIDENCE_SEGMENT_V1',
          segmentId: id(100 + index),
          firstSequence: String(sequence),
          throughSequence: String(sequence + group.length - 1),
          previousSegmentDigest: previous,
          keyId: 'test-runtime-artifact-key',
          retentionUntil: '2026-10-25T12:00:00.000000Z',
        },
        group,
        key,
      );
      const opened = openSegment(sealed.bytes, sealed.objectDigest, sealed.header, key);
      for (const record of opened.records)
        restored.push({
          recordId: record.recordId,
          evidenceClass: record.evidenceClass,
          sourceFormat: record.sourceFormat,
          occurredAt: record.occurredAt,
          receiptDigest: record.receiptDigest,
          receiptBase64: record.receiptBase64,
        });
      previous = sealed.objectDigest;
      sequence += group.length;
    }
    const result = reconstructRuntimeArtifactArchive(source, restored);
    expect(result.payload.equals(payload)).toBe(true);
    expect(result.manifest).toEqual(prepared.manifest);
    expect(result.manifest.authority).toBe('NONE');
    expect(result.manifest.currentReadiness).toBe('NOT_ESTABLISHED');
    expect(prepared.groups.at(-1)).toHaveLength(1);
    result.payload.fill(0);
    key.fill(0);
  },
);

it('binds original identity and scope independently of identical content bytes', () => {
  const payload = Buffer.from('original configuration bytes'),
    source = identity(payload);
  const first = prepareRuntimeArtifactArchive(source, payload);
  for (const change of [
    { participantId: id(9) },
    { privacyDomainId: id(9) },
    { runtimeConfigurationInputId: id(9) },
    { moduleInstallationId: id(9) },
    { moduleConfigurationGenerationId: id(9) },
    { resourceBindingsDigest: sha256('other bindings') },
    { createdAt: '2026-09-25T12:00:00.123457Z' },
  ]) {
    const other = { ...source, ...change };
    const next = prepareRuntimeArtifactArchive(other, payload);
    expect(next.manifest.identityDigest).not.toBe(first.manifest.identityDigest);
    expect(() => reconstructRuntimeArtifactArchive(other, first.groups.flat())).toThrow();
  }
});

it('rejects incomplete, reordered, substituted, corrupt and noncanonical archives', () => {
  const payload = randomBytes(65_537),
    source = identity(payload);
  const records = prepareRuntimeArtifactArchive(source, payload).groups.flat();
  for (const altered of [
    records.slice(1),
    records.slice(0, -1),
    [records[1]!, records[0]!, records[2]!],
    [records[0]!, records[0]!, records[2]!],
    [...records, records[2]!],
  ])
    expect(() => reconstructRuntimeArtifactArchive(source, altered)).toThrow();
  for (const patch of [
    { sourceFormat: 'OPENPC_CANDIDATE_PROJECTION_CHUNK_V1' },
    { evidenceClass: 'AUTHENTICATION' as const },
    { occurredAt: '2026-09-25T12:00:00.123457Z' },
    { receiptBase64: records[0]!.receiptBase64 + '\n' },
    {
      receiptBase64: Buffer.from('substitute').toString('base64'),
      receiptDigest: sha256(Buffer.from('substitute')),
    },
  ])
    expect(() =>
      reconstructRuntimeArtifactArchive(source, [
        { ...records[0]!, ...patch },
        ...records.slice(1),
      ]),
    ).toThrow();
  const last = records.at(-1)!;
  const noncanonical = Buffer.from(
    ' ' + Buffer.from(last.receiptBase64, 'base64').toString('utf8'),
  );
  expect(() =>
    reconstructRuntimeArtifactArchive(source, [
      ...records.slice(0, -1),
      {
        ...last,
        receiptBase64: noncanonical.toString('base64'),
        receiptDigest: sha256(noncanonical),
      },
    ]),
  ).toThrow();
  // Even an internally consistent rewritten chunk/manifest fails the pinned
  // full original digest; the manifest is not independent source authority.
  const manifest = JSON.parse(Buffer.from(last.receiptBase64, 'base64').toString('utf8'));
  const substituted = Buffer.from(records[0]!.receiptBase64, 'base64');
  substituted[0] = substituted[0]! ^ 1;
  manifest.chunks[0].digest = sha256(substituted);
  const rewritten = Buffer.from(canonicalJson(manifest));
  expect(() =>
    reconstructRuntimeArtifactArchive(source, [
      {
        ...records[0]!,
        receiptBase64: substituted.toString('base64'),
        receiptDigest: sha256(substituted),
      },
      records[1]!,
      { ...last, receiptBase64: rewritten.toString('base64'), receiptDigest: sha256(rewritten) },
    ]),
  ).toThrow();
});

it('refuses oversized payloads and caller-supplied clearance fields', () => {
  const bytes = Buffer.from([0xa0]),
    source = identity(bytes);
  expect(() =>
    prepareRuntimeArtifactArchive(
      { ...source, configurationBytes: RUNTIME_ARTIFACT_MAX_BYTES + 1 },
      bytes,
    ),
  ).toThrow();
  expect(() => prepareRuntimeArtifactArchive(source, Buffer.from([0xa1]))).toThrow();
  const { manifest } = prepareRuntimeArtifactArchive(source, bytes);
  for (const patch of [
    { eligible: true },
    { referencesCleared: true },
    { authority: 'GRANTED' },
    { currentReadiness: 'READY' },
    { class: 'AUDIT_EVIDENCE' },
  ])
    expect(() => runtimeArtifactArchiveManifest.parse({ ...manifest, ...patch })).toThrow();
});

const sourceUrl = process.env.OPENPC_RUNTIME_ARTIFACT_SOURCE_DATABASE_URL;
const sourceCases = process.env.OPENPC_RUNTIME_ARTIFACT_SOURCE_CASES;
it.runIf(sourceUrl !== undefined && sourceCases !== undefined)(
  'reads original runtime artifact bytes with the real scoped database role without mutation or clearance',
  async () => {
    const cases = z
      .array(
        z.strictObject({
          participantId: z.uuidv7(),
          privacyDomainId: z.uuidv7(),
          runtimeConfigurationInputId: z.uuidv7(),
          configurationDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
          configurationBytes: z.number().int().min(1).max(RUNTIME_ARTIFACT_MAX_BYTES),
        }),
      )
      .min(1)
      .max(16)
      .parse(JSON.parse(sourceCases!));
    const pool = new Pool({ connectionString: sourceUrl, max: 1 });
    try {
      for (const item of cases) {
        const request = {
          participantId: item.participantId,
          privacyDomainId: item.privacyDomainId,
          runtimeConfigurationInputId: item.runtimeConfigurationInputId,
        };
        const read = async (denials: boolean) => {
          const client = await pool.connect();
          try {
            await client.query('begin');
            await client.query(
              "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
              [item.participantId, item.privacyDomainId, id(999)],
            );
            if (denials) {
              await expect(
                readRuntimeArtifactArchiveSource(client, { ...request, privacyDomainId: id(998) }),
              ).rejects.toThrow();
              await expect(
                readRuntimeArtifactArchiveSource(client, {
                  ...request,
                  runtimeConfigurationInputId: id(998),
                }),
              ).rejects.toThrow();
              await client.query(
                "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
              );
              await expect(readRuntimeArtifactArchiveSource(client, request)).rejects.toThrow();
              await client.query(
                "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
              );
            }
            const prepared = await readRuntimeArtifactArchiveSource(client, request);
            expect(prepared.manifest.identity.configurationDigest).toBe(item.configurationDigest);
            expect(prepared.manifest.identity.configurationBytes).toBe(item.configurationBytes);
            const restored = reconstructRuntimeArtifactArchive(
              prepared.manifest.identity,
              prepared.groups.flat(),
            );
            expect(sha256(restored.payload)).toBe(item.configurationDigest);
            restored.payload.fill(0);
            expect(prepared.manifest.authority).toBe('NONE');
            return prepared.manifest;
          } finally {
            await client.query('rollback');
            client.release(true);
          }
        };
        // A fresh connection retains the same original identity/bytes. Nothing
        // is inserted into custody, retired, reselected or replayed by this test.
        expect(await read(false)).toEqual(await read(true));
      }
    } finally {
      await pool.end();
    }
  },
);
