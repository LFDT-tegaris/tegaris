import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, link, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { readQualificationObserverFile } from '../../../services/identity-service/src/domain/qualification-observer-client.ts';
import {
  qualificationObserverPackagedCases,
  qualificationObserverPackagedInputSchema,
  runQualificationObserverPackagedCase,
  verifyQualificationObserverFiles,
} from './qualification-observer-packaged.mjs';
test('packaged observation dispatch requires nine explicit normal-process cases', () => {
  assert.equal(qualificationObserverPackagedCases.length, 9);
  assert.equal(new Set(qualificationObserverPackagedCases).size, 9);
  assert.equal(
    qualificationObserverPackagedInputSchema.safeParse({ qualified: true, nativeProcess: true })
      .success,
    false,
  );
});
function preparedInput() {
  const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const root = join(tmpdir(), 'qualification-observer-contract');
  const digest = 'sha256:' + 'a'.repeat(64);
  return {
    schemaVersion: 1,
    caseName: 'positive-root-restart',
    root,
    ownerToken: 'a'.repeat(64),
    project: 'openpc-local-e2e-' + 'a'.repeat(12),
    hostBundle: root + '/host.mjs',
    hostInputFile: root + '/input',
    adminConnectionFile: root + '/admin',
    actors: [0, 1].map((n) => ({
      containerId: String(n + 1).repeat(64),
      imageId: digest,
      clientInputFile: root + '/client-' + n + '/input',
      clientCertificateFile: root + '/client-' + n + '/cert',
      clientPrivateKeyFile: root + '/client-' + n + '/key',
      initialPins: {
        schemaVersion: 1,
        installationId: id(n + 1),
        participantId: id(3),
        privacyDomainId: id(4),
        environmentId: 'test-observer',
        operationsInstallationDigest: digest,
        peer: {
          principalId: id(n + 5),
          credentialId: id(n + 7),
          participantEpoch: '1',
          principalEpoch: '1',
          credentialEpoch: '1',
          workloadId: 'urn:workload:' + n,
          keyDigest: digest,
          certificateDigest: digest,
        },
        daemonId: 'test-daemon',
        engineEndpoint: 'unix:///var/run/docker.sock',
        expectedUid: 1000,
        executable: '/usr/local/bin/node',
        argv: ['/app/server.mjs'],
        memoryBytes: 268435456,
        nanoCpus: 500000000,
        pidsLimit: 32,
        mounts: [],
        tmpfsTargets: [],
        separatedFrom: [id(2 - n)],
      },
    })),
  };
}
async function ownedFiles(t) {
  const root = await realpath(
    await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir(), 'qualification-observer-')),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = preparedInput();
  const original = input.root;
  input.root = root;
  const names = ['hostBundle', 'hostInputFile', 'adminConnectionFile'];
  for (const name of names) input[name] = input[name].replace(original, root);
  for (const actor of input.actors)
    for (const name of ['clientInputFile', 'clientCertificateFile', 'clientPrivateKeyFile'])
      actor[name] = actor[name].replace(original, root);
  const files = [
    input.hostBundle,
    input.hostInputFile,
    input.adminConnectionFile,
    ...input.actors.flatMap((a) => [
      a.clientInputFile,
      a.clientCertificateFile,
      a.clientPrivateKeyFile,
    ]),
  ];
  for (const file of files) {
    await mkdir(dirname(file), { recursive: true, mode: 0o700 });
    await writeFile(file, 'fixture\n', { mode: 0o600, flag: 'wx' });
  }
  await writeFile(
    join(root, '.openpc-local-runtime-owner'),
    `openpc-local-runtime:${input.project}:${input.ownerToken}\n`,
    { mode: 0o600, flag: 'wx' },
  );
  return input;
}

test('packaged observation accepts private owned inputs outside developer home directories', async (t) => {
  const input = await ownedFiles(t);
  await chmod(input.hostBundle, 0o644);
  assert.deepEqual(await verifyQualificationObserverFiles(input), input);
});

for (const [name, change] of [
  ['readable workspace', (input) => chmod(input.root, 0o750)],
  [
    'foreign marker',
    (input) =>
      writeFile(
        join(input.root, '.openpc-local-runtime-owner'),
        'openpc-local-runtime:foreign:owner\n',
      ),
  ],
  ['public marker', (input) => chmod(join(input.root, '.openpc-local-runtime-owner'), 0o644)],
  [
    'hard-linked marker',
    (input) =>
      link(join(input.root, '.openpc-local-runtime-owner'), join(input.root, 'marker-copy')),
  ],
  [
    'sibling path prefix',
    async (input, t) => {
      const sibling = input.root + '-sibling';
      await mkdir(sibling, { mode: 0o700 });
      t.after(() => rm(sibling, { recursive: true, force: true }));
      input.hostBundle = join(sibling, 'host.mjs');
      await writeFile(input.hostBundle, 'fixture\n', { mode: 0o600 });
    },
  ],
  [
    'traversal path',
    async (input) => {
      const child = join(input.root, 'child');
      await mkdir(child, { mode: 0o700 });
      input.hostBundle = child + '/../host.mjs';
    },
  ],
  ['public host input', (input) => chmod(input.hostInputFile, 0o644)],
  ['public database connection', (input) => chmod(input.adminConnectionFile, 0o644)],
  ['public client key', (input) => chmod(input.actors[0].clientPrivateKeyFile, 0o644)],
  [
    'credential aliased as executable',
    async (input) => {
      input.hostBundle = input.adminConnectionFile;
      await chmod(input.hostBundle, 0o644);
    },
  ],
  ['group-writable executable', (input) => chmod(input.hostBundle, 0o620)],
  ['hard-linked executable', (input) => link(input.hostBundle, join(input.root, 'bundle-copy'))],
  [
    'directory instead of executable',
    async (input) => {
      await rm(input.hostBundle);
      await mkdir(input.hostBundle, { mode: 0o700 });
    },
  ],
  [
    'symbolic-link executable',
    async (input) => {
      const target = join(input.root, 'target.mjs');
      await writeFile(target, 'fixture\n', { mode: 0o600 });
      await rm(input.hostBundle);
      await symlink(target, input.hostBundle);
    },
  ],
]) {
  test(`packaged observation rejects ${name} before parsing host inputs`, async (t) => {
    const input = await ownedFiles(t);
    await change(input, t);
    await assert.rejects(() => verifyQualificationObserverFiles(input));
  });
}

test('packaged observation rejects a symbolic-link workspace', async (t) => {
  const input = await ownedFiles(t);
  const alias = input.root + '-alias';
  t.after(() => rm(alias, { force: true }));
  await symlink(input.root, alias, 'dir');
  input.root = alias;
  await assert.rejects(() => verifyQualificationObserverFiles(input));
});

test('packaged observation validates custody before reading a foreign host input', async (t) => {
  const input = await ownedFiles(t);
  input.hostInputFile = input.root + '-sibling/input.json';
  await assert.rejects(() => runQualificationObserverPackagedCase(input), {
    code: 'ERR_ASSERTION',
  });
});
test('prepared normal-process inputs reject budget, program, credential and scope substitution before runtime', () => {
  const valid = preparedInput();
  for (const caseName of qualificationObserverPackagedCases)
    assert.ok(qualificationObserverPackagedInputSchema.parse({ ...valid, caseName }));
  for (const change of [
    (v) => {
      v.actors[0].initialPins.memoryBytes = 8589934592;
    },
    (v) => {
      v.actors[0].initialPins.nanoCpus = 2000000000;
    },
    (v) => {
      v.actors[0].initialPins.argv = ['-e', 'pretend subject'];
    },
    (v) => {
      v.actors[0].initialPins.privacyDomainId = v.actors[0].initialPins.installationId;
    },
    (v) => {
      v.actors[0].initialPins.peer.credentialId = v.actors[1].initialPins.peer.credentialId;
    },
    (v) => {
      v.actors[0].clientPrivateKeyFile = v.actors[1].clientPrivateKeyFile;
    },
    (v) => {
      v.actors[0].initialPins.separatedFrom = [];
    },
    (v) => {
      v.actors[0].nativeReady = true;
    },
  ]) {
    const changed = structuredClone(valid);
    change(changed);
    assert.equal(qualificationObserverPackagedInputSchema.safeParse(changed).success, false);
  }
});
for (const caseName of qualificationObserverPackagedCases)
  test(
    'RUNTIME: packaged qualification observer ' + caseName,
    { skip: !process.env.OPENPC_QUALIFICATION_OBSERVER_CASES_FILE, timeout: 240000 },
    async () => {
      const cases = JSON.parse(
        (
          await readQualificationObserverFile(
            process.env.OPENPC_QUALIFICATION_OBSERVER_CASES_FILE,
            65536,
          )
        ).toString('utf8'),
      );
      assert.ok(Array.isArray(cases));
      const selected = cases.filter((v) => v.caseName === caseName);
      assert.equal(selected.length, 1);
      assert.deepEqual(await runQualificationObserverPackagedCase(selected[0]), {
        caseName,
        result: 'PASS',
        claim: 'PACKAGED_NATIVE_OBSERVATION_ONLY',
      });
    },
  );
