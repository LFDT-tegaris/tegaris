import { chmod, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { expect, it } from 'vitest';
import type { Pool } from 'pg';
import {
  CandidateRecoverySourceFailure,
  candidateDatabaseSecurity,
  candidateDatabaseSnapshot,
  finishCandidateRecoverySourcePhase,
} from './candidate-database-recovery-fixture.js';
import {
  assertCandidateRecoveryComparison,
  candidateRecoveryData,
  candidateRecoveryFingerprint,
  candidateRecoverySecurity,
  readCandidateRecoveryBinding,
  requireUnusedCandidateRecoveryBinding,
  retainCandidateRecoveryOriginal,
  sealCandidateRecoveryBinding,
  type CandidateRecoveryOriginal,
} from './candidate-recovery-binding.js';

const originalName = 'candidate-database-recovery.original.json';
const archiveName = 'candidate-database-recovery.dump';
const sealName = 'candidate-database-recovery.binding.json';
const secret = 'private-value-that-must-never-be-written-to-comparison-metadata';
const fingerprint = candidateRecoveryFingerprint([{ value: secret }], 1);
const example = (): CandidateRecoveryOriginal => ({
  version: 1,
  kind: 'OPENPC-CANDIDATE-RECOVERY-ORIGINAL-1',
  provenance: {
    project: 'openpc-local-e2e-abcdef123456',
    ownerDigest: 'a'.repeat(64),
    selectionDigest: 'b'.repeat(64),
    phase: 'RETIRED',
    participantId: '018f0000-0000-7000-8000-000000000001',
    privacyDomainId: '018f0000-0000-7000-8000-000000000002',
    database: 'openpc_candidate_index',
    databaseOwner: 'openpc_candidate_index_owner',
    source: {
      containerId: 'c'.repeat(64),
      imageId: `sha256:${'d'.repeat(64)}`,
      dataDirectory: '/tmp/original',
      port: 55434,
      systemIdentifier: '12345678901234567890',
      databaseOid: '16384',
    },
    target: {
      containerId: 'e'.repeat(64),
      imageId: `sha256:${'d'.repeat(64)}`,
      dataDirectory: '/tmp/target',
      port: 55435,
      systemIdentifier: '12345678901234567891',
      databaseOid: '16385',
    },
  },
  epoch: {
    exportedSnapshot: '00000003-000000AB-1',
    snapshot: '100:110:101,105',
    backendPid: 123,
    observedAt: '2026-09-25T12:00:00.000Z',
    connectionLimit: -1,
  },
  comparison: {
    data: candidateRecoveryData({
      'candidate.schema_migration': ['a'.repeat(64)],
      'candidate.store_retirement_attempt': ['b'.repeat(64)],
      'candidate.candidate_event': [],
      'candidate.outbox_event': ['c'.repeat(64)],
      'openpc_local.migration': ['d'.repeat(64)],
      'sequence.event_sequence': ['e'.repeat(64)],
    }),
    security: candidateRecoverySecurity(
      Object.fromEntries(
        [
          'relations',
          'policies',
          'functions',
          'triggers',
          'constraints',
          'schemas',
          'defaults',
          'roles',
          'databases',
          'settings',
        ].map((key) => [key, [{ secret }]]),
      ),
    ),
    control: candidateRecoveryData({ store_retirement_outcome: ['f'.repeat(64)] }, 'control.'),
    vault: [{ name: `${'f'.repeat(64)}.segment`, bytes: 200, digest: 'a'.repeat(64) }],
  },
});
async function withRoot(run: (root: string) => Promise<void>) {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'candidate-binding-'),
  );
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
// This archive-shaped fixture proves file binding only. PostgreSQL dump/restore
// and source snapshot provenance are exercised by the existing real PG caller.
const dump = Buffer.from('PGDMP\x01binary-archive-fixture');
async function prepare(root: string, original = example()) {
  await requireUnusedCandidateRecoveryBinding(root);
  await retainCandidateRecoveryOriginal(root, original);
  await writeFile(join(root, archiveName), dump, { flag: 'wx', mode: 0o600 });
  return original;
}
async function sealed(root: string) {
  const original = await prepare(root);
  await sealCandidateRecoveryBinding(root, original.provenance);
  return original;
}

it('retains original comparisons before the archive and seals exact bytes without leaking payloads', async () =>
  withRoot(async (root) => {
    const original = await prepare(root);
    const bound = await sealCandidateRecoveryBinding(root, original.provenance);
    expect(bound.original).toEqual(original);
    expect(bound.archive.bytes).toBe(dump.length);
    expect((await readFile(join(root, originalName), 'utf8')).includes(secret)).toBe(false);
    expect((await readFile(join(root, sealName), 'utf8')).includes(secret)).toBe(false);
    // An interrupted invocation after sealing consumes these original artifacts.
    expect(await readCandidateRecoveryBinding(root, original.provenance)).toEqual(bound);
    await expect(retainCandidateRecoveryOriginal(root, original)).rejects.toThrow();
    await expect(sealCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow();
    await expect(requireUnusedCandidateRecoveryBinding(root)).rejects.toThrow();
  }));

it('keeps interruption before archive or seal UNKNOWN without regenerating original metadata', async () =>
  withRoot(async (root) => {
    const original = example();
    await retainCandidateRecoveryOriginal(root, original);
    const retained = await readFile(join(root, originalName));
    await expect(sealCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow();
    await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
    await writeFile(join(root, archiveName), dump, { flag: 'wx', mode: 0o600 });
    await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
    expect(await readFile(join(root, originalName))).toEqual(retained);
  }));

for (const fault of [
  'archive changed',
  'archive swapped',
  'archive truncated',
  'original changed',
  'original truncated',
  'seal truncated',
  'original missing',
  'seal missing',
  'archive missing',
  'unknown field',
  'duplicate key',
] as const)
  it(`rejects ${fault} without replacing retained files`, async () =>
    withRoot(async (root) => {
      const original = await sealed(root);
      const archive = join(root, archiveName),
        metadata = join(root, originalName),
        seal = join(root, sealName);
      if (fault === 'archive changed')
        await writeFile(archive, Buffer.from('PGDMP\x01changed-archive-fixture'));
      if (fault === 'archive swapped') {
        await withRoot(async (other) => {
          await writeFile(join(other, archiveName), Buffer.from('PGDMP\x01another-original'), {
            mode: 0o600,
          });
          await writeFile(archive, await readFile(join(other, archiveName)));
        });
      }
      if (fault === 'archive truncated') await writeFile(archive, 'PGDMP');
      if (fault === 'original changed')
        await writeFile(
          metadata,
          (await readFile(metadata, 'utf8')).replace(
            '12345678901234567890',
            '12345678901234567899',
          ),
        );
      if (fault === 'original truncated') await writeFile(metadata, '{');
      if (fault === 'seal truncated') await writeFile(seal, '{');
      if (fault.endsWith('missing'))
        await rm(
          fault === 'original missing' ? metadata : fault === 'seal missing' ? seal : archive,
        );
      if (fault === 'unknown field')
        await writeFile(seal, (await readFile(seal, 'utf8')).replace('{', '{"trusted":true,'));
      if (fault === 'duplicate key')
        await writeFile(seal, (await readFile(seal, 'utf8')).replace('{', '{"version":1,'));
      await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
        'UNKNOWN',
      );
    }));

it('rejects swapped original cluster, database, target, phase, scope and selection provenance', async () =>
  withRoot(async (root) => {
    const original = await sealed(root);
    for (const mutate of [
      (p: typeof original.provenance) => {
        p.source.containerId = 'f'.repeat(64);
      },
      (p: typeof original.provenance) => {
        p.source.systemIdentifier = '999';
      },
      (p: typeof original.provenance) => {
        p.source.databaseOid = '999';
      },
      (p: typeof original.provenance) => {
        p.target.systemIdentifier = '999';
      },
      (p: typeof original.provenance) => {
        p.phase = 'PRISTINE';
      },
      (p: typeof original.provenance) => {
        p.privacyDomainId = '018f0000-0000-7000-8000-000000000003';
      },
      (p: typeof original.provenance) => {
        p.selectionDigest = 'f'.repeat(64);
      },
    ]) {
      const next = structuredClone(original.provenance);
      mutate(next);
      await expect(readCandidateRecoveryBinding(root, next)).rejects.toThrow('UNKNOWN');
    }
  }));

for (const name of [originalName, archiveName, sealName])
  it(`rejects unsafe permissions, symlink or hardlink for ${name}`, async () =>
    withRoot(async (root) => {
      const original = await sealed(root),
        file = join(root, name);
      await chmod(file, 0o644);
      await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
        'UNKNOWN',
      );
      await chmod(file, 0o600);
      const other = join(root, 'other');
      await link(file, other);
      await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
        'UNKNOWN',
      );
      await rm(file);
      await symlink(other, file);
      await expect(readCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
        'UNKNOWN',
      );
    }));

it('rejects an unsafe or symlinked parent and an oversized metadata file', async () =>
  withRoot(async (root) => {
    const directory = join(root, 'backup');
    await mkdir(directory, { mode: 0o700 });
    const original = await sealed(directory);
    await chmod(directory, 0o755);
    await expect(readCandidateRecoveryBinding(directory, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
    await chmod(directory, 0o700);
    const alias = join(root, 'alias');
    await symlink(directory, alias);
    await expect(readCandidateRecoveryBinding(alias, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
    await writeFile(join(directory, originalName), Buffer.alloc(4 * 1024 * 1024 + 1));
    await expect(readCandidateRecoveryBinding(directory, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
  }));

it('refuses partial dump bytes and preexisting metadata destinations before sealing', async () =>
  withRoot(async (root) => {
    const original = await prepare(root);
    await writeFile(join(root, archiveName), 'partial');
    await expect(sealCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
    await expect(readFile(join(root, sealName))).rejects.toMatchObject({ code: 'ENOENT' });
    await writeFile(join(root, archiveName), dump);
    const linkName = join(root, 'archive-link');
    await link(join(root, archiveName), linkName);
    await expect(sealCandidateRecoveryBinding(root, original.provenance)).rejects.toThrow(
      'UNKNOWN',
    );
  }));

it('detects sequence, security, ACK, outcome, sibling and payload-absence changes independently', () => {
  const expected = example().comparison;
  expect(() =>
    assertCandidateRecoveryComparison(expected, structuredClone(expected)),
  ).not.toThrow();
  for (const name of [
    'sequence.event_sequence',
    'candidate.outbox_event',
    'candidate.store_retirement_attempt',
    'candidate.candidate_event',
  ]) {
    const changed = structuredClone(expected);
    const row = changed.data.find((entry) => entry.name === name)!;
    Object.assign(row, fingerprint);
    expect(() => assertCandidateRecoveryComparison(expected, changed)).toThrow('UNKNOWN');
  }
  for (const field of ['relations', 'roles', 'policies', 'functions', 'constraints'] as const) {
    const changed = structuredClone(expected);
    changed.security[field] = candidateRecoveryFingerprint([{ changed: field }], 1);
    expect(() => assertCandidateRecoveryComparison(expected, changed)).toThrow('UNKNOWN');
  }
  const sibling = structuredClone(expected);
  sibling.data.push({ name: 'sequence.sibling', ...fingerprint });
  expect(() => assertCandidateRecoveryComparison(expected, sibling)).toThrow('UNKNOWN');
});

it('keeps PRISTINE distinct and forbids authority-shaped or incomplete original records', async () =>
  withRoot(async (root) => {
    const original = example();
    original.provenance.phase = 'PRISTINE';
    original.comparison.vault = null;
    await prepare(root, original);
    expect(
      (await sealCandidateRecoveryBinding(root, original.provenance)).original.provenance.phase,
    ).toBe('PRISTINE');
    await withRoot(async (other) => {
      await expect(
        retainCandidateRecoveryOriginal(other, {
          ...original,
          trusted: true,
        } as CandidateRecoveryOriginal),
      ).rejects.toThrow();
      const missing = structuredClone(original);
      missing.comparison.data = [];
      await expect(retainCandidateRecoveryOriginal(other, missing)).rejects.toThrow();
    });
  }));

// These are exception/ownership regressions only. They establish no PostgreSQL
// or business acceptance and never allocate a source, target or native owner.
const sourceSteps = [
  'prepare',
  'rollbackSnapshot',
  'releaseSnapshot',
  'fenceSource',
  'endSourcePool',
  'verifySourceFence',
] as const;
const falsyFailures = [undefined, null, false, 0, ''] as const;
for (const failedStep of sourceSteps)
  it(`preserves every falsy ${failedStep} failure, completes cleanup and blocks target admission`, async () => {
    for (const thrown of falsyFailures) {
      const calls: string[] = [];
      const actions = Object.fromEntries(
        sourceSteps.map((step) => [
          step,
          () => {
            calls.push(step);
            if (step === failedStep) throw thrown;
          },
        ]),
      ) as Parameters<typeof finishCandidateRecoverySourcePhase>[0];
      let rejection: unknown;
      let rejected = false;
      try {
        await finishCandidateRecoverySourcePhase(actions);
        calls.push('target-admission');
      } catch (error) {
        rejected = true;
        rejection = error;
      }
      expect(rejected).toBe(true);
      expect(rejection).toBeInstanceOf(CandidateRecoverySourceFailure);
      expect((rejection as Error).message).toContain('UNKNOWN');
      expect((rejection as Error).cause).toBe(thrown);
      expect((rejection as CandidateRecoverySourceFailure).failedSteps).toEqual([failedStep]);
      expect(calls).toEqual(sourceSteps);
    }
  });

it('retains the original undefined failure when every later cleanup and fence also fails', async () => {
  const calls: string[] = [];
  const faults = [undefined, null, false, new Error('fence unavailable'), 0, 'uncertain readback'];
  const actions = Object.fromEntries(
    sourceSteps.map((step, index) => [
      step,
      (): unknown => {
        calls.push(step);
        throw faults[index];
      },
    ]),
  ) as Parameters<typeof finishCandidateRecoverySourcePhase>[0];
  await expect(finishCandidateRecoverySourcePhase(actions)).rejects.toMatchObject({
    cause: undefined,
    failedSteps: [...sourceSteps],
  });
  expect(calls).toEqual(sourceSteps);
});

it('attempts and verifies the retained source fence even after failed prerequisite or fence acknowledgement', async () => {
  for (const failedStep of ['prepare', 'fenceSource', 'verifySourceFence'] as const)
    for (const fault of falsyFailures) {
      const calls: string[] = [];
      const action = (step: typeof failedStep) => async () => {
        calls.push(step);
        if (step === failedStep) throw fault;
      };
      await expect(
        finishCandidateRecoverySourcePhase({
          prepare: action('prepare'),
          fenceSource: action('fenceSource'),
          verifySourceFence: action('verifySourceFence'),
        }).then(() => {
          calls.push('target-admission');
        }),
      ).rejects.toMatchObject({ cause: fault });
      expect(calls).toEqual(['prepare', 'fenceSource', 'verifySourceFence']);
    }
});

it('enters target recovery only after all source cleanup and fence readback succeed exactly once', async () => {
  const calls: string[] = [];
  const actions = Object.fromEntries(
    sourceSteps.map((step) => [
      step,
      async () => {
        calls.push(step);
      },
    ]),
  ) as Parameters<typeof finishCandidateRecoverySourcePhase>[0];
  await finishCandidateRecoverySourcePhase(actions);
  calls.push('target-admission');
  expect(calls).toEqual([...sourceSteps, 'target-admission']);
});

for (const [name, observe] of [
  ['data', candidateDatabaseSnapshot],
  ['security', candidateDatabaseSecurity],
] as const)
  it(`does not hide ${name} observation rollback/release failures or replace a falsy primary`, async () => {
    for (const primary of falsyFailures) {
      const calls: string[] = [];
      const client = {
        query: async (sql: string) => {
          if (sql === 'rollback') {
            calls.push('rollback');
            throw new Error('rollback failure');
          }
          calls.push('begin');
          throw primary;
        },
        release: () => {
          calls.push('release');
          throw new Error('release failure');
        },
      };
      const pool = { connect: async () => client } as unknown as Pool;
      await expect(observe(pool)).rejects.toMatchObject({ cause: primary });
      expect(calls).toEqual(['begin', 'rollback', 'release']);
    }
  });

it('blocks admission when a successful comparison is followed by a falsy rollback or release failure', async () => {
  for (const failedStep of ['rollback', 'release'] as const)
    for (const fault of falsyFailures) {
      const calls: string[] = [];
      const client = {
        query: async (sql: string) => {
          if (sql === 'rollback') {
            calls.push('rollback');
            if (failedStep === 'rollback') throw fault;
          }
          if (sql.includes("c.relkind in ('r','p')"))
            return {
              rows: [
                { schema: 'candidate', name: 'schema_migration' },
                { schema: 'candidate', name: 'store_retirement_attempt' },
              ],
            };
          return { rows: [] };
        },
        release: () => {
          calls.push('release');
          if (failedStep === 'release') throw fault;
        },
      };
      const pool = { connect: async () => client } as unknown as Pool;
      await expect(
        candidateDatabaseSnapshot(pool).then(() => {
          calls.push('target-admission');
        }),
      ).rejects.toMatchObject({ cause: fault });
      expect(calls).toEqual(['rollback', 'release']);
    }
});
