import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

integration(
  'keeps async scheduling closed and validates the installed original-payload SQL boundary',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id(),
      eventId = id();
    const context = {
      participantId,
      privacyDomainId,
      actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
    };
    try {
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Async denial initial trust','ACTIVE',1)",
        [participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Async denial initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacyDomainId, participantId],
      );
      for (const call of [
        'select openpc.assert_notification_async_worker_owner()',
        'select openpc.notification_async_pre_effect_phase($1)',
      ]) {
        await expect(
          runScopedTransaction(runtime, context, id, (c) =>
            c.query(call, call.includes('$1') ? [eventId] : []),
          ),
        ).rejects.toMatchObject({
          code: 'P0001',
          message: 'OPS_NOTIFICATION_ASYNC_PROOF_OWNER_UNBOUND',
        });
      }
      for (const table of ['notification_async_work', 'notification_async_work_transition']) {
        expect(
          (
            await admin.query(
              "select has_table_privilege('openpc_identity_runtime',$1,'INSERT') allowed",
              ['control.' + table],
            )
          ).rows[0].allowed,
        ).toBe(false);
        await expect(
          runScopedTransaction(runtime, context, id, (c) =>
            c.query(`delete from control.${table}`),
          ),
        ).rejects.toMatchObject({ code: '42501' });
        await expect(
          runScopedTransaction(runtime, context, id, (c) =>
            c.query(`truncate control.${table} cascade`),
          ),
        ).rejects.toMatchObject({ code: '42501' });
      }
      const digest = 'sha256:' + '00'.repeat(32);
      await expect(
        runScopedTransaction(runtime, context, id, (c) =>
          c.query('select openpc.read_notification_delivery_payload_size($1,$2)', [
            eventId,
            digest,
          ]),
        ),
      ).rejects.toMatchObject({ code: 'P0001', message: 'NOTIFICATION-PREPARATION-FENCE' });
      await expect(
        runScopedTransaction(runtime, context, id, async (c) => {
          await c.query(
            "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1,0))",
            [participantId],
          );
          for (const prefix of ['notification-worker:', 'notification-installation:'])
            await c.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
              prefix + participantId + ':' + privacyDomainId,
            ]);
          return c.query('select openpc.read_notification_delivery_payload_size($1,$2)', [
            eventId,
            digest,
          ]);
        }),
      ).rejects.toMatchObject({ code: 'P0002' });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.notification_async_work where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.outbox_event where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(0);
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
);
