import { tmpdir } from 'node:os';
import { mkdtemp, writeFile, symlink, link, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { afterEach, expect, it } from 'vitest';
import {
  createQualificationObserverClient,
  qualificationObserverClientInputSchema,
  qualificationObserverCommandSchema,
  qualificationObserverResponseSchema,
  readQualificationObserverFile,
} from './qualification-observer-client.js';
const roots: string[] = [];
const scratch = process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
const id = '018f0000-0000-7000-8000-000000000001';
const input = {
  schemaVersion: 1,
  origin: 'https://172.18.0.1:8449',
  serverName: 'observer',
  serverSpkiDigest: 'sha256:' + 'a'.repeat(64),
  clientCertificateDigest: 'sha256:' + 'b'.repeat(64),
  caFile: '/run/client/ca',
  certificateFile: '/run/client/cert',
  privateKeyFile: '/run/client/key',
  observationId: id,
  operationId: id,
  requestTimeoutMs: 35000,
  connectWindowMs: 10000,
};
it('client uses exact installed endpoint, original IDs and bounded lifetimes', () => {
  expect(qualificationObserverClientInputSchema.parse(input)).toEqual(input);
  for (const patch of [
    { origin: 'http://172.18.0.1:8449' },
    { origin: 'https://observer:8449' },
    { origin: input.origin + '/redirect' },
    { requestTimeoutMs: Infinity },
    { current: true },
    { role: 'owner' },
    { privateKeyFile: '/run/client/../host-key' },
    { connectWindowMs: 99999 },
  ])
    expect(qualificationObserverClientInputSchema.safeParse({ ...input, ...patch }).success).toBe(
      false,
    );
});
it('wire cannot request another scope, bootstrap, provider lookup or currentness', () => {
  const command = { schemaVersion: 1, mode: 'READ_ORIGINAL', observationId: id, operationId: id };
  expect(qualificationObserverCommandSchema.parse(command)).toEqual(command);
  for (const patch of [
    { mode: 'PROVE' },
    { participantId: id },
    { current: true },
    { role: 'owner' },
  ])
    expect(qualificationObserverCommandSchema.safeParse({ ...command, ...patch }).success).toBe(
      false,
    );
  expect(
    qualificationObserverResponseSchema.safeParse({
      schemaVersion: 1,
      observationId: id,
      state: 'READY',
      readback: 'CURRENT',
      observationDigest: null,
    }).success,
  ).toBe(false);
});
it('disabled and invalid optional observers cannot fail independent Identity startup', async () => {
  const disabled = await createQualificationObserverClient();
  expect(await disabled.start()).toBe('DISABLED');
  await Promise.all([disabled.close(), disabled.close()]);
  expect(disabled.status()).toBe('CLOSED');
  for (const value of ['', '/unavailable/observer-input']) {
    const invalid = await createQualificationObserverClient(value);
    expect(await invalid.start()).toBe('FAILED');
    await invalid.close();
    expect(invalid.status()).toBe('CLOSED');
  }
});
it('native bounded file reader rejects aliases, sharing, permissions and oversize', async () => {
  const root = await mkdtemp(join(scratch, 'observer-input-'));
  roots.push(root);
  const file = join(root, 'input');
  await writeFile(file, 'bounded', { mode: 0o600 });
  expect((await readQualificationObserverFile(file, 7)).toString()).toBe('bounded');
  await expect(readQualificationObserverFile(file, 6)).rejects.toThrow();
  const alias = join(root, 'alias');
  await symlink(file, alias);
  await expect(readQualificationObserverFile(alias, 10)).rejects.toThrow();
  await chmod(file, 0o644);
  await expect(readQualificationObserverFile(file, 10)).rejects.toThrow();
  await chmod(file, 0o600);
  await link(file, join(root, 'hard'));
  await expect(readQualificationObserverFile(file, 10)).rejects.toThrow();
  const fifo = join(root, 'fifo');
  await promisify(execFile)('mkfifo', ['--mode=600', fifo], { timeout: 2000, maxBuffer: 1024 });
  // O_NONBLOCK must reject a FIFO with no writer without waiting for a peer.
  await expect(readQualificationObserverFile(fifo, 10)).rejects.toThrow();
});
