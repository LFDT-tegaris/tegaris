import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect } from 'vitest';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { NotificationPayloadReader } from '../../../services/control-api/src/evidence/notification-payload-reader.js';
import {
  notificationKeySelector,
  notificationKeyFile,
  NotificationKeyCustodyError,
  type NotificationKeyPreparation,
  type NotificationKeySelector,
} from '../../../services/control-api/src/evidence/notification-key-contracts.js';

const request = z.strictObject({
  selector: notificationKeySelector,
  mode: z.enum(['CONSUME', 'THROW', 'ABORT_BEFORE', 'ABORT_IN_CALLBACK']),
});
type Mode = z.infer<typeof request>['mode'];
type Reply = { status: number; body: unknown };
export type NotificationPayloadReadCall = (
  selector: NotificationKeySelector,
  mode: Mode,
  foreign?: boolean,
) => Promise<Reply>;

/** Mount in the existing PostgreSQL fixture only, using its real Evidence TLS
 * peer and producer grant. No new listener/kernel/KMS, worker impersonation or
 * delivery state. The response contains assertions, never payload/key bytes. */
export function installNotificationPayloadReadCaseRoute(
  app: FastifyInstance,
  reader: NotificationPayloadReader,
) {
  app.post('/test/notification-payload/consume', async (req, reply) => {
    const parsed = request.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ code: 'INVALID' });
    const { selector, mode } = parsed.data,
      abort = new AbortController();
    if (mode === 'ABORT_BEFORE') abort.abort();
    let borrowed: Buffer | undefined,
      digest: string | undefined,
      calls = 0;
    let failureCode: NotificationKeyCustodyError['code'] | undefined;
    try {
      await reader.consume(req.raw.socket as TLSSocket, selector, abort.signal, (bytes) => {
        borrowed = bytes;
        calls++;
        digest = sha256(bytes);
        if (mode === 'THROW') throw new Error('intentional local consumer failure');
        if (mode === 'ABORT_IN_CALLBACK') abort.abort();
        return undefined;
      });
    } catch (error) {
      failureCode = error instanceof NotificationKeyCustodyError ? error.code : 'UNAVAILABLE';
    }
    const erased = borrowed === undefined || borrowed.equals(Buffer.alloc(borrowed.length));
    return reply
      .code(failureCode ? 403 : 200)
      .send({ calls, erased, ...(failureCode ? { code: failureCode } : { digest }) });
  });
}

const select = (p: NotificationKeyPreparation): NotificationKeySelector => ({
  participantId: p.input.scope.participantId,
  privacyDomainId: p.input.scope.privacyDomainId,
  producerTrustDigest: p.input.producerTrustDigest,
  kmsInstallationDigest: p.input.kmsInstallationDigest,
  preparationId: p.preparationId,
});
const success = (reply: Reply, digest: string) => {
  expect(reply.status).toBe(200);
  expect(reply.body).toEqual({ calls: 1, erased: true, digest });
};
const denial = (reply: Reply, calls = 0, code?: NotificationKeyCustodyError['code']) => {
  expect(reply.status).toBe(403);
  expect(reply.body).toEqual({
    calls,
    erased: true,
    code: code ?? expect.stringMatching(/^(UNAVAILABLE|UNKNOWN)$/u),
  });
};

/** Read-only business use of an original produced by the real custody/publication
 * owners. The canonical caller owns exclusive fixture resources and invokes this
 * before destructive provider lifecycle cases. Vault edits below are explicit
 * corruption of this disposable test object, restored even after a failure.
 * No approval, publication, key or delivery business state is seeded here. */
export async function assertNotificationPayloadReadCases(input: {
  admin: Pool;
  call: NotificationPayloadReadCall;
  readAttempt: () => Promise<Reply>;
  original: NotificationKeyPreparation;
  otherOriginal: NotificationKeyPreparation;
  vaultDirectory: string;
  provider: {
    counters(): { prepareCalls: number; prepareEffects: number; unwrapCalls: number };
    loseNextResponse(operation: 'UNWRAP'): void;
    nextFault(value: 'STALE' | 'WRONG_NONCE' | 'RECOVERY_WRONG_SIGNER'): void;
  };
}) {
  const { original: p, call, admin, provider } = input,
    q = select(p);
  const before = provider.counters();
  const identity = async () => {
    const rows = await admin.query(
      `select p.preparation_bytes,p.preparation_digest,c.key_id,c.encryption_exchange_id,
       c.encrypted_object_digest,c.encryption_context_digest,k.record_bytes,k.record_cose
       from control.notification_key_preparation p
       join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
       join control.evidence_wrapped_key k on k.participant_id=p.participant_id
        and k.privacy_domain_id=p.privacy_domain_id and k.attempt_id=p.preparation_id and k.key_id=c.key_id
       where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    expect(rows.rowCount).toBe(1);
    return rows.rows;
  };
  const originalIdentity = await identity();
  const reconcileOriginal = async () => {
    const counts = provider.counters();
    denial(await call(q, 'CONSUME'), 0, 'UNKNOWN');
    expect(provider.counters()).toEqual(counts);
    expect(await input.readAttempt()).toMatchObject({
      status: 200,
      body: { attemptId: q.preparationId, keyId: originalIdentity[0]!.key_id },
    });
    expect(provider.counters().unwrapCalls).toBe(counts.unwrapCalls);
  };
  success(await call(q, 'CONSUME'), p.objectIntent.payloadDigest);
  denial(await call(q, 'CONSUME', true));
  denial(await call({ ...q, preparationId: '018f0000-0000-7000-8000-999999999999' }, 'CONSUME'));
  denial(await call({ ...q, privacyDomainId: '018f0000-0000-7000-8000-999999999999' }, 'CONSUME'));
  denial(await call({ ...q, kmsInstallationDigest: `sha256:${'f'.repeat(64)}` }, 'CONSUME'));
  const beforeAbort = provider.counters();
  denial(await call(q, 'ABORT_BEFORE'));
  expect(provider.counters()).toEqual(beforeAbort);
  denial(await call(q, 'THROW'), 1);
  denial(await call(q, 'ABORT_IN_CALLBACK'), 1);

  // Real deferred SQL failure/delay after local AEAD, before the KMS caller
  // observes commit. Neither may reach the consumer. Only the existing fixture's
  // exact original DECRYPT exchange is faulted; no admission is mocked.
  for (const mode of ['COMMIT_FAILURE', 'BUFFER_EXPIRY'] as const) {
    const name = `payload_read_${mode.toLowerCase()}_${q.preparationId.replaceAll('-', '')}`;
    const fault = await admin.connect();
    let triggerInstalled = false;
    try {
      await fault.query(`create function pg_temp.${name}() returns trigger language plpgsql as $$
        begin
          if convert_from(NEW.request_bytes,'UTF8')::jsonb->>'keyUse'='DECRYPT' then
            ${mode === 'COMMIT_FAILURE' ? "raise exception 'TEST_PAYLOAD_READ_COMMIT_FAILURE';" : 'perform pg_sleep(1.1);'}
          end if;
          return NEW;
        end $$`);
      await fault.query(`create constraint trigger ${name} after update on control.evidence_kms_exchange
        deferrable initially deferred for each row
        when(new.attempt_id='${q.preparationId}'::uuid and new.kind='UNWRAP' and new.state='PROVED')
        execute function pg_temp.${name}()`);
      triggerInstalled = true;
      const counts = provider.counters();
      denial(await call(q, 'CONSUME'));
      expect(provider.counters().unwrapCalls).toBe(counts.unwrapCalls + 1);
    } finally {
      try {
        if (triggerInstalled)
          await fault.query(`drop trigger ${name} on control.evidence_kms_exchange`);
      } finally {
        try {
          await fault.query(`drop function if exists pg_temp.${name}()`);
        } finally {
          fault.release();
        }
      }
    }
    if (mode === 'COMMIT_FAILURE') await reconcileOriginal();
    success(await call(q, 'CONSUME'), p.objectIntent.payloadDigest);
  }

  const path = join(input.vaultDirectory, notificationKeyFile(p)),
    bytes = await readFile(path);
  expect(input.otherOriginal.preparationId).not.toBe(p.preparationId);
  expect(input.otherOriginal.objectIntent.payloadObjectId).not.toBe(p.objectIntent.payloadObjectId);
  const copiedOriginal = await readFile(
    join(input.vaultDirectory, notificationKeyFile(input.otherOriginal)),
  );
  const parsed = JSON.parse(bytes.toString('utf8')) as {
    header: { binding: { payloadObjectId: string; recipientSetDigest: string } };
    tag: string;
  };
  const corruptions = [
    copiedOriginal,
    Buffer.concat([bytes, Buffer.from(' ')]),
    Buffer.from(
      canonicalJson({
        ...parsed,
        tag: `${parsed.tag[0] === '0' ? '1' : '0'}${parsed.tag.slice(1)}`,
      }),
    ),
    Buffer.from(
      canonicalJson({
        ...parsed,
        header: {
          ...parsed.header,
          binding: {
            ...parsed.header.binding,
            payloadObjectId: '018f0000-0000-7000-8000-999999999999',
          },
        },
      }),
    ),
    Buffer.from(
      canonicalJson({
        ...parsed,
        header: {
          ...parsed.header,
          binding: { ...parsed.header.binding, recipientSetDigest: `sha256:${'f'.repeat(64)}` },
        },
      }),
    ),
  ];
  try {
    for (const corrupted of corruptions) {
      await writeFile(path, corrupted);
      const counts = provider.counters();
      denial(await call(q, 'CONSUME'));
      expect(provider.counters()).toEqual(counts);
    }
  } finally {
    await writeFile(path, bytes);
  }
  success(await call(q, 'CONSUME'), p.objectIntent.payloadDigest);
  for (const fault of ['STALE', 'WRONG_NONCE', 'RECOVERY_WRONG_SIGNER'] as const) {
    const counts = provider.counters();
    provider.nextFault(fault);
    denial(await call(q, 'CONSUME'));
    expect(provider.counters().unwrapCalls).toBe(counts.unwrapCalls + 1);
    await reconcileOriginal();
  }
  const beforeUnknown = provider.counters();
  provider.loseNextResponse('UNWRAP');
  denial(await call(q, 'CONSUME'), 0, 'UNKNOWN');
  expect(provider.counters().unwrapCalls).toBe(beforeUnknown.unwrapCalls + 1);
  expect(
    (
      await admin.query(
        `select 1 from control.evidence_kms_exchange where participant_id=$1 and privacy_domain_id=$2
     and attempt_id=$3 and kind='UNWRAP' and state='UNKNOWN'
     and convert_from(request_bytes,'UTF8')::jsonb->>'keyUse'='DECRYPT'`,
        [q.participantId, q.privacyDomainId, q.preparationId],
      )
    ).rowCount,
  ).toBeGreaterThan(0);
  // Resolve the original uncertain exchange before another material request.
  // Readback never prepares/reseals the object or retries provider UNWRAP.
  await reconcileOriginal();
  success(await call(q, 'CONSUME'), p.objectIntent.payloadDigest);
  expect(await identity()).toEqual(originalIdentity);
  expect(await readFile(path)).toEqual(bytes);
  expect(provider.counters().prepareCalls).toBe(before.prepareCalls);
  expect(provider.counters().prepareEffects).toBe(before.prepareEffects);
}

/** Called by the existing KMS lifecycle caller AFTER its real provider rotate,
 * revoke, expiry or populated restore action. This does not perform or simulate
 * those transitions. RETAINED remains decryptable; revoked/restored-revoked,
 * expired installation/peer and unresolved provider authority must fail closed. */
export async function assertNotificationPayloadReadLifecycle(input: {
  call: NotificationPayloadReadCall;
  original: NotificationKeyPreparation;
  provider: { counters(): { prepareCalls: number; prepareEffects: number; unwrapCalls: number } };
  expectation: 'CURRENT' | 'RETAINED' | 'REVOKED' | 'RESTORED_REVOKED' | 'EXPIRED';
}) {
  const before = input.provider.counters();
  const response = await input.call(select(input.original), 'CONSUME');
  if (input.expectation === 'CURRENT' || input.expectation === 'RETAINED')
    success(response, input.original.objectIntent.payloadDigest);
  else denial(response);
  const after = input.provider.counters();
  expect(after.prepareCalls).toBe(before.prepareCalls);
  expect(after.prepareEffects).toBe(before.prepareEffects);
  // A local admission failure cannot pass as exercised provider revocation.
  expect(after.unwrapCalls).toBe(before.unwrapCalls + (input.expectation === 'EXPIRED' ? 0 : 1));
}
