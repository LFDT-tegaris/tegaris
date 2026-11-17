import { expect, it } from 'vitest';
import type { PoolClient } from 'pg';
import { readNotificationAsyncOriginal, withCurrentNotificationAsync } from './async-admission.js';
it('keeps unimplemented native async authority unavailable before queries or consumption', async () => {
  let queries = 0,
    consumed = 0;
  const client = {
    query: async () => {
      queries++;
      throw new Error('must not fabricate a reader');
    },
  } as unknown as PoolClient;
  const selector = {
    participantId: 'untrusted',
    privacyDomainId: 'untrusted',
    environmentId: 'local-test',
    generationId: 'untrusted',
    requestId: 'untrusted',
    workerInstallationDigest: 'untrusted',
  };
  await expect(readNotificationAsyncOriginal(client, selector)).rejects.toMatchObject({
    code: 'OPS_NOTIFICATION_ASYNC_OWNER_UNBOUND',
  });
  await expect(
    withCurrentNotificationAsync(client, selector, async () => {
      consumed++;
      return true;
    }),
  ).rejects.toMatchObject({ code: 'OPS_NOTIFICATION_ASYNC_OWNER_UNBOUND' });
  expect(queries).toBe(0);
  expect(consumed).toBe(0);
});
