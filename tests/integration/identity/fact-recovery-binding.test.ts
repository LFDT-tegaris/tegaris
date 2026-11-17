import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import {
  factDatabaseRecoveryCase,
  factRecoveryComparison,
  factRecoveryFiles,
  factRecoveryInputPaths,
  factRecoveryRunnerMode,
  factRecoveryTargetPort,
  retainFactRecoveryCase,
  retainFactRecoveryOriginal,
  captureFactRecoveryArchive,
  sealFactRecoveryBinding,
  readFactRecoveryBinding,
  readFactRecoveryContinuation,
  withFactRecoveryArchive,
  requireDistinctFactClusters,
  type FactRecoveryOriginal,
  type FactRecoveryProvenance,
} from './fact-recovery-binding.js';
import {
  recoveryBytes,
  recoveryHash,
  finishRecoverySourcePhase,
  observeRecovery,
} from './postgres-component-recovery.js';
import { factRecoveryImage } from './fact-recovery-binding.js';
import type { Pool } from 'pg';
const p = '018f0000-0000-7000-8000-000000000101',
  d = '018f0000-0000-7000-8000-000000000202';
const fp = { count: 0, sha256: '1'.repeat(64) };
async function prepared() {
  const root = await mkdtemp(
    join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'fact-recovery-test-'),
  );
  await chmod(root, 0o700);
  const directory = join(root, 'data/fact-database-recovery');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const token = 'a'.repeat(64),
    project = 'openpc-local-e2e-' + token.slice(0, 12),
    marker = `openpc-local-runtime:${project}:${token}\n`;
  await writeFile(join(root, '.openpc-local-runtime-owner'), marker, { mode: 0o600, flag: 'wx' });
  const passwords = {
    openpc_facts: join(root, 'secrets/fact_pg_password.txt'),
    openpc_fact_runtime: join(root, 'secrets/fact_runtime_db_password.txt'),
    openpc_policy_fact_runtime: join(root, 'secrets/policy_fact_db_password.txt'),
  };
  const input = factDatabaseRecoveryCase.parse({
    version: 1,
    phase: 'RETIRED',
    project,
    backupDirectory: directory,
    source: {
      containerId: '1'.repeat(64),
      dataDirectory: join(root, 'data/fact-pg'),
      port: 55433,
      passwords,
    },
    target: {
      containerId: '2'.repeat(64),
      dataDirectory: join(directory, 'postgres'),
      port: 55440,
      passwords,
    },
    control: {
      port: 55432,
      adminPasswordFile: join(root, 'secrets/control_pg_password.txt'),
      workerPasswordFile: join(root, 'secrets/control_worker_runtime_db_password.txt'),
    },
    participantId: p,
    privacyDomainId: d,
    ...factRecoveryInputPaths(root),
    nativeExecutable: join(directory, 'fact_retirement_owner'),
  });
  await retainFactRecoveryCase(directory, input);
  const provenance: FactRecoveryProvenance = {
    project,
    ownerDigest: recoveryHash(Buffer.from(marker)),
    selectionDigest: recoveryHash(Buffer.from(JSON.stringify(input))),
    phase: 'RETIRED',
    participantId: p,
    privacyDomainId: d,
    database: 'openpc_facts',
    databaseOwner: 'openpc_facts',
    source: {
      containerId: input.source.containerId,
      imageId: 'sha256:' + '3'.repeat(64),
      dataDirectory: input.source.dataDirectory,
      port: 55433,
      systemIdentifier: '100',
      databaseOid: '1000',
    },
    target: {
      containerId: input.target.containerId,
      imageId: 'sha256:' + '3'.repeat(64),
      dataDirectory: input.target.dataDirectory,
      port: 55440,
      systemIdentifier: '200',
      databaseOid: '1000',
    },
  };
  const comparison = factRecoveryComparison.parse({
    data: [
      'openpc_local.migration',
      'facts.canonical_fact',
      'facts.retained_fact_identity',
      'facts.signed_fact_custody',
      'facts.store_retirement_attempt',
      'facts.retired_fact_payload',
      'facts.store_retirement_outbox',
      'facts.control_admission_custody_ack',
      'facts.fleet_admission_ack',
    ]
      .sort()
      .map((name) => ({ name, ...fp })),
    security: Object.fromEntries(
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
        'indexes',
        'extensions',
      ].map((name) => [name, fp]),
    ),
    control: [{ name: 'control.store_retirement_outcome', ...fp }],
    vault: [{ name: '1'.repeat(64) + '.segment', bytes: 64, digest: '2'.repeat(64) }],
    inputs: Array.from({ length: 8 }, (_, i) => ({
      name: 'input' + i,
      bytes: 64,
      sha256: '3'.repeat(64),
    })),
  });
  const original: Omit<FactRecoveryOriginal, 'key'> = {
    version: 1,
    kind: 'OPENPC-FACT-RECOVERY-ORIGINAL-1',
    provenance,
    epoch: {
      exportedSnapshot: '00000003-00000001-1',
      snapshot: '1:2:',
      backendPid: 200,
      timelineId: 1,
      walLsn: '0/1000',
      observedAt: '2026-09-25T00:00:00.000Z',
      connectionLimit: -1,
    },
    comparison,
  };
  const dump = Buffer.from('PGDMPoriginal signed Fact private payload');
  return { root, directory, input, provenance, original, dump };
}
async function sealed() {
  const value = await prepared();
  await retainFactRecoveryOriginal(value.directory, value.original);
  await captureFactRecoveryArchive(value.directory, value.provenance, async () =>
    Buffer.from(value.dump),
  );
  await sealFactRecoveryBinding(value.directory, value.provenance);
  return value;
}
it('Fact recovery preflight binds durable originals before dump and restores only authenticated plaintext', async () => {
  const x = await prepared();
  let called = false;
  await expect(
    captureFactRecoveryArchive(x.directory, x.provenance, async () => {
      called = true;
      return x.dump;
    }),
  ).rejects.toThrow();
  expect(called).toBe(false);
  await retainFactRecoveryOriginal(x.directory, x.original);
  let supplied: Buffer | undefined;
  await captureFactRecoveryArchive(x.directory, x.provenance, async () => {
    expect((await readFile(join(x.directory, factRecoveryFiles.original))).length).toBeGreaterThan(
      0,
    );
    supplied = Buffer.from(x.dump);
    return supplied;
  });
  expect(supplied?.every((byte) => byte === 0)).toBe(true);
  await expect(readFactRecoveryBinding(x.directory, x.provenance)).rejects.toThrow();
  await sealFactRecoveryBinding(x.directory, x.provenance);
  const encrypted = await readFile(join(x.directory, factRecoveryFiles.archive));
  expect(encrypted.includes(x.dump)).toBe(false);
  expect(encrypted.subarray(0, 5).toString()).not.toBe('PGDMP');
  let restored: Buffer | undefined;
  await withFactRecoveryArchive(x.directory, x.provenance, async (bytes) => {
    expect(bytes.equals(x.dump)).toBe(true);
    restored = bytes;
  });
  expect(restored?.every((byte) => byte === 0)).toBe(true);
  const bound = await readFactRecoveryContinuation(x.root, x.input.project);
  expect(bound.input).toEqual(x.input);
});
it.each(['original', 'seal', 'archive', 'key'] as const)(
  'Fact recovery preflight rejects missing retained %s before restore',
  async (name) => {
    const x = await sealed();
    await rename(join(x.directory, factRecoveryFiles[name]), join(x.directory, 'missing-' + name));
    let calls = 0;
    await expect(
      withFactRecoveryArchive(x.directory, x.provenance, async () => {
        calls++;
      }),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  },
);
it.each(['original', 'seal', 'archive', 'key'] as const)(
  'Fact recovery preflight rejects changed retained %s before restore',
  async (name) => {
    const x = await sealed(),
      file = join(x.directory, factRecoveryFiles[name]);
    const bytes = await readFile(file);
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    await writeFile(file, bytes);
    let calls = 0;
    await expect(
      withFactRecoveryArchive(x.directory, x.provenance, async () => {
        calls++;
      }),
    ).rejects.toThrow();
    expect(calls).toBe(0);
  },
);
it('Fact recovery preflight authenticates ciphertext even when unkeyed archive digest is replaced', async () => {
  const x = await sealed(),
    archive = join(x.directory, factRecoveryFiles.archive);
  const bytes = await readFile(archive);
  bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
  await writeFile(archive, bytes);
  const seal = JSON.parse(await readFile(join(x.directory, factRecoveryFiles.seal), 'utf8'));
  seal.archive.sha256 = recoveryHash(bytes);
  await writeFile(join(x.directory, factRecoveryFiles.seal), recoveryBytes(seal));
  let called = false;
  await expect(
    withFactRecoveryArchive(x.directory, x.provenance, async () => {
      called = true;
    }),
  ).rejects.toThrow();
  expect(called).toBe(false);
});
it('Fact recovery preflight binds encrypted bytes to the original comparison through AAD', async () => {
  const x = await sealed(),
    file = join(x.directory, factRecoveryFiles.original);
  const original = JSON.parse(await readFile(file, 'utf8'));
  original.comparison.security.roles.sha256 = 'e'.repeat(64);
  const bytes = recoveryBytes(original);
  await writeFile(file, bytes);
  const seal = JSON.parse(await readFile(join(x.directory, factRecoveryFiles.seal), 'utf8'));
  seal.original = { bytes: bytes.length, sha256: recoveryHash(bytes) };
  await writeFile(join(x.directory, factRecoveryFiles.seal), recoveryBytes(seal));
  await expect(readFactRecoveryBinding(x.directory, x.provenance)).rejects.toThrow();
});
it.each(['mode', 'link', 'symlink'] as const)(
  'Fact recovery preflight rejects unsafe key %s',
  async (mode) => {
    const x = await sealed(),
      file = join(x.directory, factRecoveryFiles.key);
    if (mode === 'mode') await chmod(file, 0o644);
    if (mode === 'link') await link(file, join(x.directory, 'extra-key'));
    if (mode === 'symlink') {
      await rename(file, join(x.directory, 'original-key'));
      await symlink(join(x.directory, 'original-key'), file);
    }
    await expect(readFactRecoveryBinding(x.directory, x.provenance)).rejects.toThrow();
  },
);
it('Fact recovery preflight never replaces a key, dump or original on retry', async () => {
  const x = await sealed();
  const before = await readFile(join(x.directory, factRecoveryFiles.key));
  await expect(retainFactRecoveryOriginal(x.directory, x.original)).rejects.toThrow();
  await expect(retainFactRecoveryCase(x.directory, x.input)).rejects.toThrow();
  let dumps = 0;
  await expect(
    captureFactRecoveryArchive(x.directory, x.provenance, async () => {
      dumps++;
      return Buffer.from(x.dump);
    }),
  ).rejects.toThrow();
  expect(dumps).toBe(0);
  expect((await readFile(join(x.directory, factRecoveryFiles.key))).equals(before)).toBe(true);
});
it('Fact recovery preflight does not seal after dump failure and preserves the first original', async () => {
  const x = await prepared();
  await retainFactRecoveryOriginal(x.directory, x.original);
  await expect(
    captureFactRecoveryArchive(x.directory, x.provenance, async () => {
      throw false;
    }),
  ).rejects.toThrow();
  await expect(readFactRecoveryContinuation(x.root, x.input.project)).rejects.toThrow();
  await expect(retainFactRecoveryOriginal(x.directory, x.original)).rejects.toThrow();
});
it('Fact recovery preflight rejects drifted case, owner, cluster, scope and missing comparison classes', async () => {
  const x = await sealed();
  for (const change of [
    { participantId: d },
    { source: { ...x.provenance.source, systemIdentifier: '999' } },
    { databaseOwner: 'attacker' },
  ])
    await expect(
      readFactRecoveryBinding(x.directory, {
        ...x.provenance,
        ...change,
      } as FactRecoveryProvenance),
    ).rejects.toThrow();
  await expect(
    readFactRecoveryContinuation(x.root, 'openpc-local-e2e-' + 'b'.repeat(12)),
  ).rejects.toThrow();
  const changed = { ...x.input, target: { ...x.input.target, port: 55441 } };
  await writeFile(join(x.directory, 'case.json'), recoveryBytes(changed));
  await expect(readFactRecoveryContinuation(x.root, x.input.project)).rejects.toThrow();
  expect(() => requireDistinctFactClusters({ ...x.input, target: x.input.source })).toThrow();
  expect(() => factRecoveryComparison.parse({ ...x.original.comparison, data: [] })).toThrow();
});
it('Fact recovery preflight uses fresh random keys and nonces for distinct original cases', async () => {
  const a = await sealed(),
    b = await sealed();
  expect(
    (await readFile(join(a.directory, factRecoveryFiles.key))).equals(
      await readFile(join(b.directory, factRecoveryFiles.key)),
    ),
  ).toBe(false);
  expect(
    (await readFile(join(a.directory, factRecoveryFiles.archive))).equals(
      await readFile(join(b.directory, factRecoveryFiles.archive)),
    ),
  ).toBe(false);
});
it.each([undefined, null, false, 0, ''])(
  'Fact recovery preflight preserves falsy source failure %s while always fencing',
  async (primary) => {
    const calls: string[] = [];
    let failure: Error | undefined;
    try {
      await finishRecoverySourcePhase(
        {
          prepare: () => {
            calls.push('prepare');
            throw primary;
          },
          rollbackSnapshot: () => {
            calls.push('rollback');
            throw new Error('rollback');
          },
          releaseSnapshot: () => {
            calls.push('release');
            throw new Error('release');
          },
          fenceSource: () => {
            calls.push('fence');
          },
          endSourcePool: () => {
            calls.push('end');
            throw new Error('end');
          },
          verifySourceFence: () => {
            calls.push('verify');
          },
        },
        (cause, steps) => new Error(steps.join(','), { cause }),
      );
    } catch (error) {
      failure = error as Error;
    }
    expect(failure).toBeDefined();
    expect(failure!.cause).toBe(primary);
    expect(calls).toEqual(['prepare', 'rollback', 'release', 'fence', 'end', 'verify']);
  },
);
it('Fact recovery preflight treats a source-fence failure as failure despite successful prepare', async () => {
  const calls: string[] = [];
  await expect(
    finishRecoverySourcePhase(
      {
        prepare: () => {},
        fenceSource: () => {
          calls.push('fence');
          throw 0;
        },
        verifySourceFence: () => {
          calls.push('verify');
        },
      },
      (cause) => new Error('UNKNOWN', { cause }),
    ),
  ).rejects.toMatchObject({ cause: 0 });
  expect(calls).toEqual(['fence', 'verify']);
});
it('Fact recovery preflight propagates observation cleanup failure', async () => {
  let released = false;
  const pool = {
    connect: async () => ({
      query: async () => {
        throw false;
      },
      release: () => {
        released = true;
      },
    }),
  } as unknown as Pool;
  await expect(observeRecovery(pool, undefined, async () => 42)).rejects.toMatchObject({
    cause: false,
  });
  expect(released).toBe(true);
});
it('Fact recovery preflight rejects conflicting modes and validates current owned target port', async () => {
  const x = await prepared();
  expect(factRecoveryRunnerMode([])).toBe('fresh');
  expect(factRecoveryRunnerMode(['--retained'])).toBe('retained');
  expect(factRecoveryRunnerMode(['--preflight'])).toBe('preflight');
  expect(() => factRecoveryRunnerMode(['--preflight'], '1')).toThrow();
  expect(() => factRecoveryRunnerMode(['--preflight', '--fresh'])).toThrow();
  expect(() => factRecoveryRunnerMode(['--fresh'], '1')).toThrow();
  expect(() => factRecoveryRunnerMode(['--retained'], '0')).toThrow();
  const inspection = {
    Id: x.input.target.containerId,
    Image: x.provenance.target.imageId,
    State: { Running: true, OOMKilled: false },
    Config: {
      Image: factRecoveryImage,
      Labels: { 'io.openpc.test-owner': x.root, 'io.openpc.recovery-role': 'fact-target' },
    },
    HostConfig: {
      Privileged: false,
      NetworkMode: 'bridge',
      Memory: 1073741824,
      MemorySwap: 1073741824,
      NanoCpus: 750000000,
      PidsLimit: 256,
      SecurityOpt: ['no-new-privileges:true'],
    },
    Mounts: [
      {
        Destination: '/var/lib/postgresql',
        Source: x.input.target.dataDirectory,
        Type: 'bind',
        RW: true,
      },
    ],
    NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '127.0.0.1', HostPort: '55445' }] } },
  };
  expect(factRecoveryTargetPort(x.input, x.root, x.provenance.target.imageId, inspection)).toBe(
    55445,
  );
  expect(x.input.target.port).toBe(55440);
  for (const change of [
    { HostConfig: { ...inspection.HostConfig, Privileged: true } },
    {
      Config: {
        ...inspection.Config,
        Labels: { ...inspection.Config.Labels, 'io.openpc.recovery-role': 'candidate-target' },
      },
    },
    { NetworkSettings: { Ports: { '5432/tcp': [{ HostIp: '0.0.0.0', HostPort: '55445' }] } } },
  ])
    expect(() =>
      factRecoveryTargetPort(x.input, x.root, x.provenance.target.imageId, {
        ...inspection,
        ...change,
      }),
    ).toThrow();
});
