import { readFileSync } from 'node:fs';
import type { PoolClient } from 'pg';
import { it, expect } from 'vitest';
import {
  installInitialNotificationCompletionWorker,
  fenceNotificationCompletionWorkerInstallation,
  withdrawNotificationCompletionWorker,
  readNotificationCompletionWorkerOriginal,
} from './completion-worker-installation.js';
it.each([
  installInitialNotificationCompletionWorker,
  fenceNotificationCompletionWorkerInstallation,
  withdrawNotificationCompletionWorker,
  readNotificationCompletionWorkerOriginal,
])('rejects malformed selectors before touching an internal owner', async (operation) => {
  let touches = 0;
  // Deliberately unavailable owner proves early negative validation only; never a
  // substitute for actual database installation/withdrawal/transaction acceptance.
  const client = new Proxy(
    {},
    {
      get() {
        touches++;
        throw new Error('Owner touched');
      },
    },
  ) as PoolClient;
  await expect(operation(client, { authorized: true })).rejects.toThrow();
  expect(touches).toBe(0);
});
it('requires installed guards and separate runtime/installer roles, exact replay and irreversible withdrawal', () => {
  const source = readFileSync(
    new URL('./completion-worker-installation.ts', import.meta.url),
    'utf8',
  );
  expect(source).toContain('assert_notification_completion_worker_installation_owner');
  expect(source).toContain("installer ? 'openpc_control_owner' : 'openpc_control_runtime'");
  expect(source).toContain("prior.rows[0]!.state !== 'ACTIVE'");
  expect(source).toContain('installation_bytes.equals(valid.bytes)');
  expect(source).toContain("set state='REVOKED'");
  expect(source).not.toMatch(
    /set state='ACTIVE'|on conflict|insert into control\.(work_item|notification_source_inbox|notification_source_cursor)/iu,
  );
});

/** Prepared for the canonical real PG/TLS driver; not executed by the component
 * cases above. Both pools must use their real scoped roles, sockets must come
 * from actual verified TLS, and profiles from privileged initial trust setup.
 * No callback mints authority, no Identity/SQL mock and no internal state seed. */
export async function assertNotificationCompletionWorkerInstallationLifecycle(args: {
  ownerPool: import('pg').Pool;
  runtimePool: import('pg').Pool;
  kernel: import('../../../identity-service/src/domain/identity-kernel.js').IdentityKernel;
  socket: import('node:tls').TLSSocket;
  successorSocket: import('node:tls').TLSSocket;
  original: unknown;
  successor: unknown;
}) {
  const { runScopedTransaction } =
    await import('../../../identity-service/src/db/scoped-transaction.js');
  const { localOperationId } =
    await import('../../../identity-service/src/domain/local-operation-id.js');
  const { notificationCompletionWorkerInstallation } =
    await import('./completion-worker-installation-contract.js');
  const { withNotificationCompletionWorkerPeer, assertNotificationCompletionWorkerCurrent } =
    await import('../../../identity-service/src/domain/notification-completion-worker.js');
  const input = notificationCompletionWorkerInstallation.parse(args.original);
  const successor = notificationCompletionWorkerInstallation.parse(args.successor);
  expect(successor.pins.profileId).not.toBe(input.pins.profileId);
  expect(successor.pins.participantId).toBe(input.pins.participantId);
  expect(successor.pins.privacyDomainId).toBe(input.pins.privacyDomainId);
  const context = {
    participantId: input.pins.participantId,
    privacyDomainId: input.pins.privacyDomainId,
    actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  };
  const initial = await runScopedTransaction(args.ownerPool, context, localOperationId, (c) =>
    installInitialNotificationCompletionWorker(c, input),
  );
  const q = {
    participantId: context.participantId,
    privacyDomainId: context.privacyDomainId,
    installationDigest: initial,
  };
  expect(
    await runScopedTransaction(args.ownerPool, context, localOperationId, (c) =>
      installInitialNotificationCompletionWorker(c, input),
    ),
  ).toBe(initial);
  let captured:
    | {
        client: PoolClient;
        admission: import('../../../identity-service/src/domain/notification-completion-worker.js').NotificationCompletionWorkerAdmission;
      }
    | undefined;
  await withNotificationCompletionWorkerPeer(
    args.runtimePool,
    args.kernel,
    args.socket,
    q,
    async (client, admission) => {
      captured = { client, admission };
      await assertNotificationCompletionWorkerCurrent(admission, client, q);
      await expect(
        assertNotificationCompletionWorkerCurrent({ ...admission }, client, q),
      ).rejects.toThrow();
      // The second genuine owner transaction cannot withdraw across a live shared
      // installation fence. No long wait, sleep or competing runtime is started.
      await expect(
        runScopedTransaction(args.ownerPool, context, localOperationId, (c) =>
          withdrawNotificationCompletionWorker(c, q),
        ),
      ).rejects.toThrow();
      await assertNotificationCompletionWorkerCurrent(admission, client, q);
    },
  );
  if (!captured) throw new Error('Actual admission was not reached');
  await expect(
    assertNotificationCompletionWorkerCurrent(captured.admission, captured.client, q),
  ).rejects.toThrow();
  await runScopedTransaction(args.ownerPool, context, localOperationId, (c) =>
    withdrawNotificationCompletionWorker(c, q),
  );
  const retained = await runScopedTransaction(args.runtimePool, context, localOperationId, (c) =>
    readNotificationCompletionWorkerOriginal(c, q),
  );
  expect(retained.state).toBe('REVOKED');
  expect(retained.original.input).toEqual(input);
  let revokedCallback = false;
  await expect(
    withNotificationCompletionWorkerPeer(
      args.runtimePool,
      args.kernel,
      args.socket,
      q,
      async () => {
        revokedCallback = true;
      },
    ),
  ).rejects.toThrow();
  expect(revokedCallback).toBe(false);
  await expect(
    runScopedTransaction(args.ownerPool, context, localOperationId, (c) =>
      installInitialNotificationCompletionWorker(c, input),
    ),
  ).rejects.toThrow();
  const successorDigest = await runScopedTransaction(
    args.ownerPool,
    context,
    localOperationId,
    (c) => installInitialNotificationCompletionWorker(c, successor),
  );
  expect(successorDigest).not.toBe(initial);
  await withNotificationCompletionWorkerPeer(
    args.runtimePool,
    args.kernel,
    args.successorSocket,
    { ...q, installationDigest: successorDigest },
    async (client, admission) => {
      await assertNotificationCompletionWorkerCurrent(admission, client, {
        ...q,
        installationDigest: successorDigest,
      });
      const old = await readNotificationCompletionWorkerOriginal(client, q);
      expect(old.state).toBe('REVOKED');
      expect(old.original.bytes).toEqual(retained.original.bytes);
    },
  );
  return { original: q, successor: { ...q, installationDigest: successorDigest } };
}
