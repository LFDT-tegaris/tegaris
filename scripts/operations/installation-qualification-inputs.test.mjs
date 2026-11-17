import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import {
  installationQualificationInputSchema,
  parseInstallationQualificationArguments,
  readInstallationQualificationInputs,
} from './installation-qualification-inputs.mjs';
const id = (n) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
export const hostInputExample = {
  schemaVersion: 1,
  repositoryRoot: '/srv/openpc',
  identityConnectionFile: '/run/observer/identity',
  ownerConnectionFile: '/run/observer/owner',
  tls: {
    caFile: '/run/observer/ca',
    certificateFile: '/run/observer/cert',
    privateKeyFile: '/run/observer/key',
  },
  listen: { address: '172.19.0.1', port: 8449 },
  deployment: {
    selection: { participantId: id(1), privacyDomainId: id(2), installationId: id(3) },
    intent: { observationId: id(4), operationId: id(5) },
  },
  resources: { memoryGiB: 1, externalMemoryGiB: 1.75, peakDiskGiB: 10 },
  drainTimeoutMs: 40000,
};

async function privateInputFixture(t) {
  assert.ok(process.env.OPENPC_PNC_TMP_ROOT, 'Bind the existing external test scratch root');
  const scratch = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT, 'qualification-input-'));
  t.after(() => rm(scratch, { recursive: true }));
  // Synthetic paths only: the input reader must not open connections, keys or a listener.
  const input = {
    ...structuredClone(hostInputExample),
    repositoryRoot: scratch,
    identityConnectionFile: join(scratch, 'identity'),
    ownerConnectionFile: join(scratch, 'owner'),
    tls: {
      caFile: join(scratch, 'ca'),
      certificateFile: join(scratch, 'certificate'),
      privateKeyFile: join(scratch, 'key'),
    },
  };
  return { file: join(scratch, 'input.json'), input };
}

test('owned qualification byte reader preserves valid exact input', async (t) => {
  const { file, input } = await privateInputFixture(t);
  await writeFile(file, JSON.stringify(input), { mode: 0o600, flag: 'wx' });
  assert.deepEqual(await readInstallationQualificationInputs(file), input);
});

const privateMarker = 'qualification-fixture-private-value';
for (const [name, replace] of Object.entries({
  'top-level duplicate': (raw) =>
    raw.replace('"schemaVersion":1', `"schemaVersion":"${privateMarker}","schemaVersion":1`),
  'nested duplicate': (raw) =>
    raw.replace('"memoryGiB":1', `"memoryGiB":"${privateMarker}","memoryGiB":1`),
  'escaped duplicate': (raw) =>
    raw.replace('"schemaVersion":1', `"schemaVersion":"${privateMarker}","\\u0073chemaVersion":1`),
})) {
  test(`owned qualification byte reader rejects ${name} without raw diagnostics`, async (t) => {
    const { file, input } = await privateInputFixture(t);
    await writeFile(file, replace(JSON.stringify(input)), { mode: 0o600, flag: 'wx' });
    await assert.rejects(
      () => readInstallationQualificationInputs(file),
      (error) => {
        assert.ok(error instanceof InstallationConfigError);
        assert.equal(error.code, 'OPS_CONFIG_INVALID');
        assert.equal(error.reason, 'MALFORMED_JSON');
        assert.equal(error.message, 'OPS_CONFIG_INVALID: MALFORMED_JSON');
        assert.ok(!error.message.includes(privateMarker));
        assert.ok(!error.message.includes(file));
        return true;
      },
    );
  });
}

test('host installation consumes only bounded exact inputs and original IDs', () => {
  assert.deepEqual(installationQualificationInputSchema.parse(hostInputExample), hostInputExample);
  assert.deepEqual(parseInstallationQualificationArguments(['--serve', '/run/observer/input']), {
    mode: '--serve',
    inputFile: '/run/observer/input',
  });
});
for (const [name, patch] of Object.entries({
  current: { current: true },
  inlineKey: { privateKey: 'not-a-key' },
  rootWildcard: { listen: { address: '0.0.0.0', port: 8449 } },
  unboundedHost: { resources: { ...hostInputExample.resources, memoryGiB: Infinity } },
  missingBudget: { resources: undefined },
  unboundedDrain: { drainTimeoutMs: 100000 },
  sameConnection: { ownerConnectionFile: hostInputExample.identityConnectionFile },
  traversal: { repositoryRoot: '/srv/../etc' },
  wrongKeyScope: {
    keyOriginal: {
      selection: { ...hostInputExample.deployment.selection, privacyDomainId: id(9) },
      attemptId: id(7),
    },
  },
}))
  test('host input rejects ' + name, () =>
    assert.equal(
      installationQualificationInputSchema.safeParse({ ...hostInputExample, ...patch }).success,
      false,
    ),
  );
for (const args of [
  [],
  ['--serve'],
  ['--bootstrap', '/root/config'],
  ['--serve', './relative'],
  ['--serve', '/run/config', '--set-role'],
])
  test('host executable rejects argument ' + args.join(' '), () =>
    assert.throws(() => parseInstallationQualificationArguments(args)),
  );
