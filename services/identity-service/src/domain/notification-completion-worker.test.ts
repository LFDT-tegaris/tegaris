import { readFileSync } from 'node:fs';
import type { Pool, PoolClient } from 'pg';
import { TLSSocket } from 'node:tls';
import { Socket } from 'node:net';
import type { IdentityKernel } from './identity-kernel.js';
import { it, expect } from 'vitest';
import {
  withNotificationCompletionWorkerPeer,
  assertNotificationCompletionWorkerCurrent,
  admitNotificationCompletionDispositionPhase,
  admitNotificationCompletionDispositionReceipt,
  installNotificationCompletionSqlBridge,
  type NotificationCompletionWorkerAdmission,
} from './notification-completion-worker.js';
const selector = {
  participantId: '01900000-0000-7000-8000-000000000001',
  privacyDomainId: '01900000-0000-7000-8000-000000000002',
  installationDigest: `sha256:${'1'.repeat(64)}`,
};
it('rejects an unauthenticated real socket before database, kernel or callback access', async () => {
  let touches = 0;
  const unavailable = new Proxy(
      {},
      {
        get() {
          touches++;
          throw new Error('Owner touched');
        },
      },
    ),
    socket = new TLSSocket(new Socket());
  try {
    await expect(
      withNotificationCompletionWorkerPeer(
        unavailable as Pool,
        unavailable as IdentityKernel,
        socket,
        selector,
        async () => {
          touches++;
        },
      ),
    ).rejects.toThrow();
    expect(touches).toBe(0);
  } finally {
    socket.destroy();
  }
});
it('rejects caller-fabricated or copied admission regardless of metadata', async () => {
  const fake = Object.freeze({ installation: {}, authorityDigest: `sha256:${'1'.repeat(64)}` });
  await expect(
    assertNotificationCompletionWorkerCurrent(
      fake as NotificationCompletionWorkerAdmission,
      {} as PoolClient,
      selector,
    ),
  ).rejects.toThrow('Notification completion worker admission unavailable');
  await expect(
    admitNotificationCompletionDispositionPhase(
      fake as NotificationCompletionWorkerAdmission,
      {} as PoolClient,
      selector,
      selector.participantId,
      'PUBLISH',
    ),
  ).rejects.toThrow('Notification completion worker admission unavailable');
});
it('rejects fabricated receipt admission before reading supplied signed bytes or SQL owners', async () => {
  let touched = false;
  const client = new Proxy(
    {},
    {
      get() {
        touched = true;
        throw new Error('Unexpected query');
      },
    },
  );
  await expect(
    admitNotificationCompletionDispositionReceipt(
      {} as NotificationCompletionWorkerAdmission,
      client as PoolClient,
      selector,
      selector.participantId,
      'PUBLISH',
      { outcome: 'SIGNED', coseHex: '00' },
    ),
  ).rejects.toThrow('Notification completion worker admission unavailable');
  expect(touched).toBe(false);
});
it('requires dedicated fixed host trust and cannot replace an installed bridge', () => {
  const pool = {} as Pool;
  expect(() => installNotificationCompletionSqlBridge(pool, Buffer.alloc(31))).toThrow();
  installNotificationCompletionSqlBridge(pool, Buffer.alloc(32, 1));
  expect(() => installNotificationCompletionSqlBridge(pool, Buffer.alloc(32, 2))).toThrow();
});
it('uses real same-client Identity confirmation and clears live admission on every exit', () => {
  const source = readFileSync(
    new URL('./notification-completion-worker.ts', import.meta.url),
    'utf8',
  );
  for (const text of [
    'withAuthenticatedWorkloadPeer',
    'await confirmPeer()',
    'active.delete(admission)',
    'entry.client !== client',
    'peer.credentialId !== p.workloadCredentialId',
    'peer.workloadEpoch !== p.workloadEpoch',
    'peer.keyId !== p.workloadKeyDigest',
    'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
  ])
    expect(source.replace(/\s+/gu, ' ')).toContain(text);
  expect(source).not.toContain('withNotificationDeliveryWorkerPeer');
});
