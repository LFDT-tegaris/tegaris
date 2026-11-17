import { randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { sha256 } from '../configuration/digest.js';
import { sealSegment } from './segment.js';
import { prepareRuntimeArtifactArchive } from './runtime-artifact-archive-contract.js';
import {
  nextRuntimeArtifactArchiveRecords,
  retainRuntimeArtifactArchive,
} from './runtime-artifact-archive-custody.js';

const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
function fixture() {
  const bytes = randomBytes(7 * 65536),
    key = randomBytes(32);
  const identity = {
    participantId: id(1),
    privacyDomainId: id(2),
    runtimeConfigurationInputId: id(3),
    moduleInstallationId: id(4),
    moduleConfigurationGenerationId: id(5),
    configurationDigest: sha256(bytes),
    configurationBytes: bytes.length,
    resourceBindingsDigest: sha256([]),
    createdAt: '2026-09-25T12:00:00.123456Z',
  };
  const scope = { participantId: id(1), privacyDomainId: id(2), streamId: 'artifact-unit' };
  const prepared = prepareRuntimeArtifactArchive(identity, bytes);
  let sequence = 1,
    previous: string | null = null;
  const groups = prepared.groups.map((group, index) => {
    const sealed = sealSegment(
      {
        ...scope,
        version: 'OPENPC_EVIDENCE_SEGMENT_V1',
        segmentId: id(100 + index),
        firstSequence: String(sequence),
        throughSequence: String(sequence + group.length - 1),
        previousSegmentDigest: previous,
        keyId: 'artifact-key',
        retentionUntil: '2026-10-25T12:00:00.000000Z',
      },
      group,
      key,
    );
    const rows = group.map((record, n) => ({
      ...record,
      sequence: String(sequence + n),
      header: sealed.header,
      objectDigest: sealed.objectDigest,
      encrypted: sealed.bytes,
    }));
    sequence += group.length;
    previous = sealed.objectDigest;
    return rows;
  });
  return { scope, prepared, key, groups };
}
function reader(rows: unknown[], retired = false) {
  let inserts = 0;
  const client = {
    query: async (sql: string) => {
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [], rowCount: 1 };
      if (sql.includes('evidence_projection_retirement'))
        return { rows: [], rowCount: retired ? 1 : 0 };
      if (sql.startsWith('select c.record_id')) return { rows, rowCount: rows.length };
      if (sql.startsWith('insert into')) {
        inserts++;
        throw new Error('unexpected write');
      }
      throw new Error('unexpected query');
    },
  } as unknown as PoolClient;
  return { client, inserts: () => inserts };
}
it('resumes the first wholly absent group after authenticating retained encrypted originals', async () => {
  const f = fixture();
  for (let n = 0; n <= f.groups.length; n++) {
    const db = reader(f.groups.slice(0, n).flat());
    expect(
      await nextRuntimeArtifactArchiveRecords(db.client, f.scope, f.prepared, async () => f.key),
    ).toEqual(f.prepared.groups[n] ?? []);
    expect(db.inserts()).toBe(0);
  }
});
it('rejects partial groups, gaps, altered retained metadata, ciphertext and wrong keys before progress', async () => {
  const f = fixture();
  const alterations = [
    f.groups[0]!.slice(1),
    f.groups[1]!,
    [{ ...f.groups[0]![0]!, receiptDigest: sha256('changed') }, ...f.groups[0]!.slice(1)],
    f.groups[0]!.map((row) => ({ ...row, encrypted: Buffer.alloc(row.encrypted.length) })),
  ];
  for (const rows of alterations)
    await expect(
      nextRuntimeArtifactArchiveRecords(
        reader(rows).client,
        f.scope,
        f.prepared,
        async () => f.key,
      ),
    ).rejects.toThrow();
  await expect(
    nextRuntimeArtifactArchiveRecords(reader(f.groups[0]!).client, f.scope, f.prepared, async () =>
      randomBytes(32),
    ),
  ).rejects.toThrow();
});
it('rejects cross-scope packets and retired catalogue entries and cannot index an incomplete archive', async () => {
  const f = fixture();
  await expect(
    nextRuntimeArtifactArchiveRecords(
      reader([]).client,
      { ...f.scope, privacyDomainId: id(9) },
      f.prepared,
      async () => f.key,
    ),
  ).rejects.toThrow();
  await expect(
    nextRuntimeArtifactArchiveRecords(
      reader([], true).client,
      f.scope,
      f.prepared,
      async () => f.key,
    ),
  ).rejects.toThrow();
  const db = reader(f.groups[0]!);
  expect(
    await retainRuntimeArtifactArchive(db.client, f.scope, f.prepared.manifest, async () => f.key),
  ).toBe(false);
  expect(db.inserts()).toBe(0);
});
