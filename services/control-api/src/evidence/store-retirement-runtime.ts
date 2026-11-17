import { createPrivateKey } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import type { Pool } from 'pg';
import { z } from 'zod';
import { StoreRetirementDispatcher } from './store-retirement-dispatcher.js';
import { retirementHost, retirementWireDigest } from './store-retirement-wire.js';
import { PostgresStoreRetirementWorkerStore } from './store-retirement-worker-store.js';

export const storeRetirementRuntimeConfiguration = z.strictObject({
  host: retirementHost,
  verifierKeyFile: z.string().startsWith('/'),
  controlPrivateKeyFile: z.string().startsWith('/'),
  targetConfigurationFile: z.string().startsWith('/'),
});

async function privateFile(path: string, maximum: number) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum || (stat.mode & 0o077) !== 0)
      throw new Error('Installed retirement key unavailable');
    const bytes = await file.readFile();
    if (!bytes.length || bytes.length > maximum)
      throw new Error('Installed retirement key changed');
    return bytes;
  } finally {
    await file.close();
  }
}

export async function openStoreRetirementRuntime(
  pool: Pool,
  configuration: z.infer<typeof storeRetirementRuntimeConfiguration>,
) {
  const config = storeRetirementRuntimeConfiguration.parse(configuration);
  const secret = await privateFile(config.verifierKeyFile, 32);
  let key: Buffer | undefined;
  let store: PostgresStoreRetirementWorkerStore | undefined;
  try {
    key = await privateFile(config.controlPrivateKeyFile, 4096);
    store = new PostgresStoreRetirementWorkerStore(pool, config.host, secret);
    const dispatcher = new StoreRetirementDispatcher(
      store,
      config.host,
      createPrivateKey(key),
      config.targetConfigurationFile,
    );
    const installed = store;
    return {
      hostDigest: retirementWireDigest(config.host),
      async runPending(signal: AbortSignal) {
        let failed = false;
        for (const attemptId of await installed.pendingAttempts()) {
          if (signal.aborted) break;
          try {
            await dispatcher.runAttempt(attemptId);
          } catch {
            failed = true;
          }
        }
        if (failed) throw new Error('Retirement reconciliation pending');
      },
      close() {
        installed.close();
      },
    };
  } catch (error) {
    store?.close();
    throw error;
  } finally {
    secret.fill(0);
    key?.fill(0);
  }
}
