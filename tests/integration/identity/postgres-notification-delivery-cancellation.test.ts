import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { readNotificationDeliveryCancellationCause } from '../../../services/control-api/src/notifications/delivery-cancellation-state.js';
import { notificationRevision } from '../../../services/control-api/src/notifications/endpoint-binding.js';

/** The existing real API fixture driver supplies identifiers only, after it has
 * performed supported endpoint CREATE/VERIFY/UPDATE with user auth and step-up.
 * No SQL-seeded operation, receipt, decision, delivery or intermediate state.
 * These cases cover historical cause/RLS/declaration admission, not successful
 * cancellation signing, gateway reconciliation or whole N2b acceptance. */
const fixtureSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  causeOperationId: z.uuidv7(),
  endpointId: z.uuidv7(),
  endpointRevision: notificationRevision,
});
const fixtureFile = process.env.OPENPC_NOTIFICATION_CANCELLATION_FIXTURE;
const enabled = fixtureFile !== undefined;
function blocked(owner: string): never {
  throw new Error(`BLOCKED notification cancellation: ${owner}`);
}
async function fixture() {
  if (!fixtureFile) blocked('public endpoint UPDATE fixture');
  const path = fixtureFile!;
  const stat = await import('node:fs/promises').then((fs) => fs.stat(path));
  if (!stat.isFile() || stat.size > 4096) blocked('bounded identifier fixture');
  return fixtureSchema.parse(JSON.parse(await readFile(path, 'utf8')));
}
async function runtime() {
  const url = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  if (!url) blocked('existing runtime PostgreSQL URL');
  const pool = new Pool({ connectionString: url, max: 2 });
  const role = await pool.query<{ allowed: boolean }>(
    `select not rolsuper and not rolbypassrls and pg_has_role(current_user,'openpc_control_runtime','USAGE') allowed from pg_roles where rolname=current_user`,
  );
  if (role.rows[0]?.allowed !== true) {
    await pool.end();
    blocked('non-bypass runtime principal');
  }
  return pool;
}
it('requires a closed cause identifier fixture rather than supplied authority or success', () => {
  const sample = {
    participantId: '01900000-0000-7000-8000-000000000001',
    privacyDomainId: '01900000-0000-7000-8000-000000000002',
    causeOperationId: '01900000-0000-7000-8000-000000000003',
    endpointId: '01900000-0000-7000-8000-000000000004',
    endpointRevision: '2',
  };
  expect(fixtureSchema.parse(sample)).toEqual(sample);
  for (const extra of [
    { authorized: true },
    { state: 'SUCCEEDED' },
    { signedReceipt: 'caller-data' },
    { cancelRequested: true },
  ])
    expect(() => fixtureSchema.parse({ ...sample, ...extra })).toThrow();
});
let causePassed = false;
it.runIf(process.env.OPENPC_I02_RUNTIME_DATABASE_URL !== undefined)(
  'keeps final cancellation writes closed until its native publication owner is complete',
  async () => {
    const pool = await runtime();
    try {
      for (const table of ['notification_delivery_cancellation']) {
        const rows = await pool.query(
          `select has_table_privilege(current_user,$1,'INSERT') can_insert,
            has_table_privilege(current_user,$1,'UPDATE') can_update,
            has_table_privilege(current_user,$1,'DELETE') can_delete,
            relrowsecurity and relforcerowsecurity protected from pg_class where oid=$1::regclass`,
          [`control.${table}`],
        );
        expect(rows.rows).toEqual([
          { can_insert: false, can_update: false, can_delete: false, protected: true },
        ]);
        await expect(
          pool.query(`insert into control.${table} default values`),
        ).rejects.toMatchObject({ code: '42501' });
      }
    } finally {
      await pool.end();
    }
  },
);
it.runIf(enabled)(
  'reads the original authenticated public UPDATE and consumed step-up after a fresh database connection',
  async () => {
    const q = await fixture();
    const read = async () => {
      const pool = await runtime();
      try {
        return await runScopedTransaction(
          pool,
          {
            participantId: q.participantId,
            privacyDomainId: q.privacyDomainId,
            actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
          },
          localOperationId,
          async (client) => {
            await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
            return readNotificationDeliveryCancellationCause(client, q);
          },
        );
      } finally {
        await pool.end();
      }
    };
    const first = await read();
    expect(first.operationId).toBe(q.causeOperationId);
    expect(first.successorRevision).toBe((BigInt(q.endpointRevision) + 1n).toString());
    expect(await read()).toEqual(first);
    causePassed = true;
  },
);
it.runIf(enabled)(
  'rejects foreign scope and wrong predecessor without any mutation or current endpoint credential',
  async () => {
    if (!causePassed) blocked('original cause prerequisite failed');
    const q = await fixture(),
      pool = await runtime();
    try {
      for (const altered of [
        { ...q, endpointRevision: (BigInt(q.endpointRevision) + 1n).toString() },
        { ...q, privacyDomainId: localOperationId() },
        { ...q, causeOperationId: localOperationId() },
      ])
        await expect(
          runScopedTransaction(
            pool,
            {
              participantId: q.participantId,
              privacyDomainId: q.privacyDomainId,
              actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
            },
            localOperationId,
            async (client) => {
              await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
              return readNotificationDeliveryCancellationCause(client, altered);
            },
          ),
        ).rejects.toThrow();
    } finally {
      await pool.end();
    }
  },
);
it.runIf(enabled)(
  'keeps cancellation originals immutable under the actual installed runtime role',
  async () => {
    const q = await fixture(),
      pool = await runtime();
    try {
      const installed = await pool.query<{ present: boolean }>(
        "select to_regclass('control.notification_delivery_cancellation') is not null present",
      );
      if (installed.rows[0]?.present !== true)
        blocked('canonical generated cancellation migration');
      const protectedTable = await pool.query<{ protected: boolean }>(
        "select relrowsecurity and relforcerowsecurity protected from pg_class where oid='control.notification_delivery_cancellation'::regclass",
      );
      expect(protectedTable.rows[0]?.protected).toBe(true);
      await expect(
        runScopedTransaction(
          pool,
          {
            participantId: q.participantId,
            privacyDomainId: q.privacyDomainId,
            actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
          },
          localOperationId,
          async (client) =>
            client.query(
              'update control.notification_delivery_cancellation set transition=transition where false',
            ),
        ),
      ).rejects.toThrow();
      await expect(
        runScopedTransaction(
          pool,
          {
            participantId: q.participantId,
            privacyDomainId: q.privacyDomainId,
            actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
          },
          localOperationId,
          async (client) =>
            client.query('delete from control.notification_delivery_cancellation where false'),
        ),
      ).rejects.toThrow();
    } finally {
      await pool.end();
    }
  },
);
