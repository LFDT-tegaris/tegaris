import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readlink } from 'node:fs/promises';
import {
  readInstallationProcessIdentity,
  readInstallationProcessIsolation,
  installationProcessIsolationSchema,
  installationProcessIdentitySchema,
} from './installation-process-observation.mjs';
test('native Linux identity and namespaces come from this live process', async () => {
  const actual = await readInstallationProcessIsolation(process.pid);
  assert.equal(actual.process.uid, process.getuid());
  assert.equal(actual.process.executable, await readlink(`/proc/${process.pid}/exe`));
  assert.equal(actual.cgroup, await readFile(`/proc/${process.pid}/cgroup`, 'utf8'));
  assert.ok(actual.process.startedAtMs <= Date.now());
  for (const name of ['mnt', 'pid', 'net', 'ipc', 'uts', 'user', 'cgroup'])
    assert.equal(actual.namespaces[name], await readlink(`/proc/${process.pid}/ns/${name}`));
  assert.deepEqual(await readInstallationProcessIdentity(process.pid), actual.process);
});
test('malformed integer observation returns schema denial, not a BigInt exception', () => {
  assert.equal(installationProcessIdentitySchema.safeParse({ startTicks: 'max' }).success, false);
});
for (const pid of [0, -1, NaN, Infinity, 1.1, '1', Number.MAX_SAFE_INTEGER + 1])
  test(`invalid process selector fails before procfs use: ${String(pid)}`, async () => {
    await assert.rejects(readInstallationProcessIdentity(pid));
  });
test('malformed namespace and caller currentness are rejected', async () => {
  const actual = await readInstallationProcessIsolation(process.pid);
  assert.equal(
    installationProcessIsolationSchema.safeParse({ ...actual, current: true }).success,
    false,
  );
  assert.equal(
    installationProcessIsolationSchema.safeParse({
      ...actual,
      namespaces: { ...actual.namespaces, net: 'caller' },
    }).success,
    false,
  );
});
