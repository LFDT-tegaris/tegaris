import { createHash } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = adminUrl ? it : it.skip;
const action = 'ACT-POLICY_SETS_CREATE_RESOURCE-V1';

// Only initial identity trust is provisioned; draft effects use HTTP.
integration(
  'creates scoped policy drafts atomically with current authority and restart-safe exact replay',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const pid = id(),
      privacy = id();
    const fixtures: Awaited<ReturnType<typeof contractAdministrationFixture>>[] = [];
    const counts = async () =>
      (
        await admin.query(
          `select
    (select count(*)::int from control.policy where participant_id=$1) policies,
    (select count(*)::int from control.idempotency_record where participant_id=$1 and action_intent_id=$2) operations,
    (select count(*)::int from control.mutation_evidence where participant_id=$1 and action_intent_id=$2) evidence,
    (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_type='policy-set') events,
    (select count(*)::int from control.policy_generation where participant_id=$1) generations`,
          [pid, action],
        )
      ).rows[0];
    try {
      const fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        pid,
        privacy,
      );
      fixtures.push(fixture);
      const fields = {
        participantId: `urn:openpc:participant:${pid}`,
        name: 'First policy draft',
        activeVersionDigest: null,
      };
      for (const invalid of [
        { name: '' },
        { name: ' ' },
        { name: 'x'.repeat(161) },
        { extra: true },
        { activeVersionDigest: 'wrong' },
        { activeVersionDigest: undefined },
        { participantId: `urn:openpc:resource:${pid}` },
      ]) {
        expect(
          (await fixture.attemptMutation('policy-sets', action, { ...fields, ...invalid })).status,
        ).toBe(400);
      }
      expect(
        (
          await fixture.attemptMutation('policy-sets', action, {
            ...fields,
            activeVersionDigest: `sha256:${'12'.repeat(32)}`,
          })
        ).status,
      ).toBe(409);
      expect(await counts()).toEqual({
        policies: 0,
        operations: 0,
        evidence: 0,
        events: 0,
        generations: 0,
      });

      // Failure after the domain INSERT must roll back domain, operation and outbox.
      await admin.query(`create function openpc.policy_set_test_failure() returns trigger language plpgsql as $$begin
      if NEW.action_intent_id='ACT-POLICY_SETS_CREATE_RESOURCE-V1' then raise exception 'test evidence unavailable'; end if;
      return NEW; end$$;
      create trigger policy_set_test_failure before insert on control.mutation_evidence for each row execute function openpc.policy_set_test_failure()`);
      const intent = fixture.ordinaryMutation('policy-sets', action, fields);
      expect((await intent.call()).status).toBeGreaterThanOrEqual(400);
      expect(await counts()).toEqual({
        policies: 0,
        operations: 0,
        evidence: 0,
        events: 0,
        generations: 0,
      });
      await admin.query(
        'drop trigger policy_set_test_failure on control.mutation_evidence; drop function openpc.policy_set_test_failure()',
      );
      const simultaneous = await Promise.all([intent.call(), intent.call()]);
      expect(simultaneous[0], JSON.stringify(simultaneous)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', revision: '1' },
      });
      expect(simultaneous[1]).toEqual(simultaneous[0]);
      const operation = simultaneous[0]!.body;
      const resourceId = String(operation.resourceRef).slice(-36);
      expect(await counts()).toEqual({
        policies: 1,
        operations: 1,
        evidence: 1,
        events: 1,
        generations: 0,
      });
      const detail = await fixture.read(`policy-sets/${String(operation.resourceRef)}`);
      expect(detail.status).toBe(200);
      expect(detail.body).toMatchObject({
        policySetId: `urn:openpc:policy-set:${resourceId}`,
        participantId: fields.participantId,
        name: fields.name,
        state: 'DRAFT',
        activeVersionDigest: null,
        revision: '1',
      });
      expect(Object.keys(detail.body).sort()).toEqual([
        'activeVersionDigest',
        'createdAt',
        'name',
        'participantId',
        'policySetId',
        'revision',
        'state',
        'updatedAt',
      ]);
      const page = await fixture.read('policy-sets?filter=state:eq:DRAFT&limit=1');
      expect(page.status).toBe(200);
      expect(page.body).toMatchObject({
        items: [detail.body],
        total: '1',
        completeness: 'COMPLETE',
        nextCursor: null,
      });
      expect((await intent.call({ ...intent.body, name: 'Altered intent' })).status).toBe(412);
      expect((await fixture.attemptMutation('policy-sets', action, fields)).status).toBe(409);
      expect(
        (await intent.call({ ...intent.body, actionIntentDigest: `sha256:${'00'.repeat(32)}` }))
          .status,
      ).toBe(400);
      await fixture.restartConfiguration();
      expect((await fixture.read(`policy-sets/${String(operation.resourceRef)}`)).body).toEqual(
        detail.body,
      );
      expect((await fixture.read(`operations/${String(operation.operationId)}`)).body).toEqual(
        operation,
      );
      expect(await intent.call()).toEqual(simultaneous[0]);
      const proof = (
        await admin.query(
          `select m.evidence_cbor,m.evidence_digest,e.payload_cbor,e.payload_digest
      from control.mutation_evidence m join control.outbox_event e on e.participant_id=m.participant_id
       and e.privacy_domain_id=m.privacy_domain_id and e.aggregate_id=m.aggregate_id and e.event_type='policy-set.created.v1'
      where m.participant_id=$1 and m.operation_id=$2`,
          [pid, operation.operationId],
        )
      ).rows;
      expect(proof).toHaveLength(1);
      for (const prefix of ['evidence', 'payload'])
        expect(createHash('sha256').update(proof[0][`${prefix}_cbor`]).digest()).toEqual(
          proof[0][`${prefix}_digest`],
        );

      const foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      fixtures.push(foreign);
      expect((await foreign.read(`policy-sets/${String(operation.resourceRef)}`)).status).toBe(403);
      expect((await foreign.read('policy-sets')).body).toMatchObject({
        items: [],
        total: '0',
        authorizedEmpty: true,
      });
      const foreignPrivacy = id();
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Other policy scope','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [foreignPrivacy, pid],
      );
      const scoped = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        pid,
        foreignPrivacy,
        { existingScope: true },
      );
      fixtures.push(scoped);
      await scoped.selectPrivacyContext();
      expect((await scoped.read(`policy-sets/${String(operation.resourceRef)}`)).status).toBe(403);
      expect((await scoped.read('policy-sets')).body).toMatchObject({
        items: [],
        total: '0',
        authorizedEmpty: true,
      });
      expect(
        (
          await fixture.read('policy-sets', {
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${foreignPrivacy}`,
          })
        ).status,
      ).toBe(403);
      await admin.query(
        `update control.assignment set state='REVOKED',row_version=row_version+1 where participant_id=$1 and principal_id=$2`,
        [pid, fixture.makerId],
      );
      expect((await intent.call()).status).toBe(403);
      expect((await fixture.read(`policy-sets/${String(operation.resourceRef)}`)).status).toBe(403);
      expect(await counts()).toEqual({
        policies: 1,
        operations: 1,
        evidence: 1,
        events: 1,
        generations: 0,
      });
    } finally {
      await admin.query(
        'drop trigger if exists policy_set_test_failure on control.mutation_evidence; drop function if exists openpc.policy_set_test_failure()',
      );
      for (const fixture of fixtures.reverse()) await fixture.close();
      await admin.end();
    }
  },
  120_000,
);
