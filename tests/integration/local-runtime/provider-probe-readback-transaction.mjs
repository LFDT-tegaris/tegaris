import { setTimeout as delay } from 'node:timers/promises';

// Only database readback opts into retries. The provider request and its
// qualification operation remain outside this boundary.
export async function withProviderReadbackRollback(
  pool,
  consume,
  { retryContention = false } = {},
) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const client = await pool.connect();
    let failed = false,
      first,
      result,
      cleanupFailed = false;
    try {
      result = await consume(client);
    } catch (error) {
      failed = true;
      first = error;
    }
    const cleanup = (error) => {
      process.stderr.write('OPENPC_PROVIDER_READBACK_CLEANUP|UNKNOWN\n');
      if (!failed) first = error;
      failed = true;
      cleanupFailed = true;
    };
    await client.query('rollback').catch(cleanup);
    try {
      client.release();
    } catch (error) {
      cleanup(error);
    }
    if (!failed) return result;
    const busy =
      first?.code === '40001' || (first?.code === 'P0001' && first?.message === 'PC-DATA-6007');
    if (!retryContention || cleanupFailed || !busy || attempt === 2) throw first;
    await delay(10 * 3 ** attempt);
  }
}
