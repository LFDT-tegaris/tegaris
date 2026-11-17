import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { digest } from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

integration(
  'commits real public notification state, authority, signed receipt and outbox atomically with replay and restart',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const pid = id(),
      privacy = id();
    const fixture = await contractAdministrationFixture(admin, runtimeUrl!, pid, privacy);
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const counts = async () =>
      (
        await admin.query(
          `select
    (select count(*)::int from control.notification where participant_id=$1) items,
    (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='notification') receipts,
    (select count(*)::int from control.receipt_signing_attempt where participant_id=$1) attempts,
    (select count(*)::int from control.outbox_event where participant_id=$1) events,
    (select count(*)::int from control.mutation_evidence where participant_id=$1) inputs`,
          [pid],
        )
      ).rows[0];
    const create = () =>
      fixture.ordinaryMutation('notifications', 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1', {
        participantId: `urn:openpc:participant:${pid}`,
        severity: 'WARNING',
        messageKey: 'evidence.export.completed',
        resourceRef: `urn:openpc:resource:${id()}`,
      });
    try {
      const originalCounts = await counts();
      const prepared = create();
      expect([403, 409]).toContain((await prepared.call()).status);
      expect(await counts()).toEqual(originalCounts);
      signing = await evidenceGovernanceSigningFixture(admin, pid, privacy, 'notification');
      await fixture.restartConfiguration(signing.evidence);
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        signing.faults.mode = mode;
        expect([403, 409]).toContain((await prepared.call()).status);
        expect(await counts()).toEqual(originalCounts);
      }
      signing.faults.mode = undefined;
      // Fault the durable outbox after signing and receipt insertion. Every
      // internal owner remains real; no business state is manufactured.
      await admin.query(`create function openpc.test_notification_outbox_failure() returns trigger language plpgsql as $$
        begin if NEW.aggregate_type='notification' then raise exception 'TEST_NOTIFICATION_OUTBOX_FAILURE'; end if; return NEW; end $$;
        create trigger test_notification_outbox_failure before insert on control.outbox_event
        for each row execute function openpc.test_notification_outbox_failure()`);
      try {
        const calls = signing.faults.calls;
        expect((await prepared.call()).status).toBe(409);
        expect(signing.faults.calls).toBe(calls + 1);
        expect(await counts()).toEqual(originalCounts);
      } finally {
        await admin.query(
          'drop trigger test_notification_outbox_failure on control.outbox_event; drop function openpc.test_notification_outbox_failure()',
        );
      }
      const created = await prepared.call();
      expect(created, JSON.stringify(created)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', truthState: 'SUCCESS', revision: '1' },
      });
      const ref = String(created.body.resourceRef),
        itemId = ref.slice(-36);
      const signed = async () =>
        (
          await admin.query(
            `select receipt_cbor,cose_sign1,receipt_digest,
      before_state_preimage,after_state_preimage,receipt_id,operation_id
      from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 order by after_revision`,
            [pid, privacy, itemId],
          )
        ).rows;
      expect((await prepared.call()).body).toEqual(created.body);
      const afterCreate = await counts();
      expect(afterCreate).toEqual({ items: 1, receipts: 1, attempts: 1, events: 1, inputs: 1 });
      expect(
        (
          await prepared.call({
            ...prepared.body,
            reason: 'Different intent under the original key.',
          })
        ).status,
      ).toBe(412);
      expect(await counts()).toEqual(afterCreate);
      const read = () => fixture.read(`notifications/${ref}`);
      expect(await read()).toMatchObject({
        status: 200,
        body: { state: 'UNREAD', revision: '1', severity: 'WARNING' },
      });
      expect(Object.keys((await read()).body).sort()).toEqual(
        [
          'notificationId',
          'participantId',
          'severity',
          'state',
          'resourceRef',
          'messageKey',
          'revision',
          'createdAt',
          'updatedAt',
        ].sort(),
      );
      // A caller with runtime SQL privileges cannot mutate without the exact
      // signed effect, or evade the deferred check by changing request context.
      const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
      try {
        for (const tamper of [true, false]) {
          const client = await runtime.connect();
          try {
            await client.query('begin');
            await client.query(
              "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
              [pid, privacy, id(), 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1'],
            );
            if (tamper) {
              await expect(
                client.query(
                  `update control.notification set state='ACKNOWLEDGED',revision=revision+1,message_key='forged.message' where notification_id=$1`,
                  [itemId],
                ),
              ).rejects.toThrow('DATA-6021-NOTIFICATION-ACKNOWLEDGE');
            } else {
              expect(
                (
                  await client.query(
                    `update control.notification set state='ACKNOWLEDGED',revision=revision+1 where notification_id=$1`,
                    [itemId],
                  )
                ).rowCount,
              ).toBe(1);
              await client.query(
                "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
                [pid, privacy, id(), 'ACT-NOTIFICATIONS_READ_RESOURCE-V1'],
              );
              await expect(client.query('set constraints all immediate')).rejects.toThrow(
                'query returned no rows',
              );
            }
          } finally {
            await client.query('rollback');
            client.release();
          }
          expect(await counts()).toEqual(afterCreate);
          expect(await read()).toMatchObject({
            status: 200,
            body: { state: 'UNREAD', revision: '1' },
          });
        }
      } finally {
        await runtime.end();
      }
      const command = (revision: string, actor: 'maker' | 'checker' = 'maker') => {
        const action = 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1';
        return fixture.ordinaryMutation(
          `notifications/${ref}/acknowledge`,
          action,
          {
            targetRef: ref,
            expectedRevision: revision,
            inputDigest: digest({
              actionIntentId: action,
              targetRef: ref,
              expectedRevision: revision,
              transition: 'ACKNOWLEDGE',
            }),
          },
          'POST',
          actor,
        );
      };
      const invalid = command('1');
      expect(
        (await invalid.call({ ...invalid.body, inputDigest: `sha256:${'00'.repeat(32)}` })).status,
      ).toBe(412);
      expect(await counts()).toEqual(afterCreate);
      const contenders = [command('1'), command('1', 'checker')];
      const results = await Promise.all(contenders.map((c) => c.call()));
      expect(results.map((r) => r.status).sort(), JSON.stringify(results)).toEqual([202, 412]);
      const complete = contenders[results[0]!.status === 202 ? 0 : 1]!;
      const completed = results[results[0]!.status === 202 ? 0 : 1]!;
      expect(await read()).toMatchObject({
        status: 200,
        body: {
          state: 'ACKNOWLEDGED',
          revision: '2',
          severity: 'WARNING',
          messageKey: 'evidence.export.completed',
        },
      });
      expect(await counts()).toEqual({ items: 1, receipts: 2, attempts: 2, events: 2, inputs: 2 });
      const afterAcknowledgement = await counts();
      expect((await command('1').call()).status).toBe(412);
      expect((await command('2').call()).status).toBe(412);
      expect(await counts()).toEqual(afterAcknowledgement);
      const receipts = await signed();
      expect(receipts).toHaveLength(2);
      for (const [index, row] of receipts.entries()) {
        expect(verifyReceiptCose(signing.publicKey, row.receipt_cbor, row.cose_sign1)).toBe(true);
        expect(decodeAdmittedReceipt(row.receipt_cbor)).toMatchObject({
          aggregateId: itemId,
          before: { existence: index === 0 ? 0 : 1, revision: BigInt(index) },
          after: { existence: 1, revision: BigInt(index + 1) },
        });
        const binding = await admin.query(
          `select count(*)::int n from control.outbox_event e
        join control.receipt_signing_attempt a on a.attempt_id=e.receipt_id and a.participant_id=e.participant_id
        where e.participant_id=$1 and a.operation_id=$2 and a.attempt_id=$3 and a.payload_cbor=$4`,
          [pid, row.operation_id, row.receipt_id, row.receipt_cbor],
        );
        expect(binding.rows[0].n).toBe(1);
      }
      await fixture.restartConfiguration(signing.evidence);
      expect(await read()).toMatchObject({
        status: 200,
        body: { state: 'ACKNOWLEDGED', revision: '2' },
      });
      expect((await fixture.read(`operations/${created.body.operationId}`)).body).toEqual(
        created.body,
      );
      expect((await fixture.read(`operations/${completed.body.operationId}`)).body).toEqual(
        completed.body,
      );
      expect((await complete.call()).body).toEqual(completed.body);
      expect((await prepared.call()).body).toEqual(created.body);
      expect(await signed()).toEqual(receipts);
      expect(await counts()).toEqual({ items: 1, receipts: 2, attempts: 2, events: 2, inputs: 2 });
      foreign = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect([403, 409]).toContain((await foreign.read(`notifications/${ref}`)).status);
      expect([403, 409]).toContain(
        (
          await fixture.read(`notifications/${ref}`, {
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${foreign.privacyDomainId}`,
          })
        ).status,
      );
      const list = await fixture.read('notifications?filter=state%3Aeq%3AACKNOWLEDGED');
      expect(list.status, JSON.stringify(list.body)).toBe(200);
      expect(list.body).toMatchObject({
        items: [{ notificationId: ref, state: 'ACKNOWLEDGED' }],
        total: '1',
        authorizedEmpty: false,
      });
      const empty = await fixture.read('notifications?filter=state%3Aeq%3AUNREAD');
      expect(empty).toMatchObject({
        status: 200,
        body: { items: [], total: '0', authorizedEmpty: true },
      });
      const foreignList = await foreign.read('notifications');
      expect(foreignList).toMatchObject({
        status: 200,
        body: { items: [], total: '0', authorizedEmpty: true },
      });
    } finally {
      await foreign?.close();
      await fixture.close();
      signing?.close();
      await admin.end();
    }
  },
  120000,
);
