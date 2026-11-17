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
  'commits real public work-item state, authority, signed receipt and outbox atomically with replay and restart',
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
    (select count(*)::int from control.work_item where participant_id=$1) items,
    (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='work-item') receipts,
    (select count(*)::int from control.receipt_signing_attempt where participant_id=$1) attempts,
    (select count(*)::int from control.outbox_event where participant_id=$1) events,
    (select count(*)::int from control.mutation_evidence where participant_id=$1) inputs`,
          [pid],
        )
      ).rows[0];
    const create = () =>
      fixture.ordinaryMutation('work-items', 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1', {
        participantId: `urn:openpc:participant:${pid}`,
        kind: 'DELIVERY_FAILURE',
        assigneeRef: null,
        resourceRef: `urn:openpc:resource:${id()}`,
      });
    try {
      const originalCounts = await counts();
      const prepared = create();
      expect([403, 409]).toContain((await prepared.call()).status);
      expect(await counts()).toEqual(originalCounts);
      signing = await evidenceGovernanceSigningFixture(admin, pid, privacy, 'work-item');
      await fixture.restartConfiguration(signing.evidence);
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        signing.faults.mode = mode;
        expect([403, 409]).toContain((await prepared.call()).status);
        expect(await counts()).toEqual(originalCounts);
      }
      signing.faults.mode = undefined;
      // Fault the durable outbox after signing and receipt insertion. Every
      // internal owner remains real; no business state is manufactured.
      await admin.query(`create function openpc.test_work_item_outbox_failure() returns trigger language plpgsql as $$
        begin if NEW.aggregate_type='work-item' then raise exception 'TEST_WORK_ITEM_OUTBOX_FAILURE'; end if; return NEW; end $$;
        create trigger test_work_item_outbox_failure before insert on control.outbox_event
        for each row execute function openpc.test_work_item_outbox_failure()`);
      try {
        const calls = signing.faults.calls;
        expect((await prepared.call()).status).toBe(409);
        expect(signing.faults.calls).toBe(calls + 1);
        expect(await counts()).toEqual(originalCounts);
      } finally {
        await admin.query(
          'drop trigger test_work_item_outbox_failure on control.outbox_event; drop function openpc.test_work_item_outbox_failure()',
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
      const read = () => fixture.read(`work-items/${ref}`);
      expect(await read()).toMatchObject({
        status: 200,
        body: { state: 'OPEN', revision: '1', assigneeRef: null },
      });
      expect(JSON.stringify((await read()).body)).not.toContain('reason');
      const update = fixture.ordinaryMutation(
        `work-items/${ref}`,
        'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
        {
          expectedRevision: '1',
          replacementDigest: `sha256:${'ab'.repeat(32)}`,
        },
        'PATCH',
      );
      const updated = await update.call();
      expect(updated, JSON.stringify(updated)).toMatchObject({
        status: 202,
        body: { revision: '2' },
      });
      expect((await update.call()).body).toEqual(updated.body);
      const afterUpdate = await counts();
      const stale = fixture.ordinaryMutation(
        `work-items/${ref}`,
        'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
        {
          expectedRevision: '1',
          replacementDigest: `sha256:${'cd'.repeat(32)}`,
        },
        'PATCH',
      );
      expect((await stale.call()).status).toBe(412);
      expect(await counts()).toEqual(afterUpdate);
      const command = (
        transition: 'CLAIM' | 'COMPLETE',
        revision: string,
        actor: 'maker' | 'checker',
      ) => {
        const action = `ACT-OPERATIONS_UPDATE_${transition}-V1`;
        return fixture.ordinaryMutation(
          `work-items/${ref}/${transition.toLowerCase()}`,
          action,
          {
            targetRef: ref,
            expectedRevision: revision,
            inputDigest: digest({
              actionIntentId: action,
              targetRef: ref,
              expectedRevision: revision,
              transition,
            }),
          },
          'POST',
          actor,
        );
      };
      const claims = [command('CLAIM', '2', 'maker'), command('CLAIM', '2', 'checker')];
      const results = await Promise.all(claims.map((c) => c.call()));
      expect(results.map((r) => r.status).sort(), JSON.stringify(results)).toEqual([202, 412]);
      const winner = results[0]!.status === 202 ? 'maker' : 'checker';
      const loser = winner === 'maker' ? 'checker' : 'maker';
      const claimant = fixture.governance[winner].principalId;
      expect(await read()).toMatchObject({
        status: 200,
        body: { state: 'CLAIMED', revision: '3', assigneeRef: `urn:openpc:resource:${claimant}` },
      });
      const beforeWrongCompletion = await counts();
      expect((await command('COMPLETE', '3', loser).call()).status).toBe(412);
      expect(await counts()).toEqual(beforeWrongCompletion);
      const complete = command('COMPLETE', '3', winner);
      const completed = await complete.call();
      expect(completed, JSON.stringify(completed)).toMatchObject({
        status: 202,
        body: { revision: '4' },
      });
      expect(await counts()).toEqual({ items: 1, receipts: 4, attempts: 4, events: 4, inputs: 4 });
      const receipts = await signed();
      expect(receipts).toHaveLength(4);
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
        body: { state: 'COMPLETED', revision: '4' },
      });
      expect((await complete.call()).body).toEqual(completed.body);
      expect((await prepared.call()).body).toEqual(created.body);
      expect(await signed()).toEqual(receipts);
      expect(await counts()).toEqual({ items: 1, receipts: 4, attempts: 4, events: 4, inputs: 4 });
      foreign = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect([403, 409]).toContain((await foreign.read(`work-items/${ref}`)).status);
      expect([403, 409]).toContain(
        (
          await fixture.read(`work-items/${ref}`, {
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${foreign.privacyDomainId}`,
          })
        ).status,
      );
      const list = await fixture.read('work-items?filter=state%3Aeq%3ACOMPLETED');
      expect(list.status, JSON.stringify(list.body)).toBe(200);
      expect(list.body).toMatchObject({ items: [{ workItemId: ref, state: 'COMPLETED' }] });
      const empty = await fixture.read('work-items?filter=state%3Aeq%3AOPEN');
      expect(empty).toMatchObject({ status: 200, body: { items: [] } });
      const foreignList = await foreign.read('work-items');
      expect(foreignList).toMatchObject({ status: 200, body: { items: [] } });
    } finally {
      await foreign?.close();
      await fixture.close();
      signing?.close();
      await admin.end();
    }
  },
  120000,
);
