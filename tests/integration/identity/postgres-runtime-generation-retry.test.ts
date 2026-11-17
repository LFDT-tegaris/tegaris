import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const source = process.env.OPENPC_RUNTIME_GENERATION_RETRY_SOURCE;
const admittedWithdrawal = process.env.OPENPC_RUNTIME_GENERATION_RETRY_ADMITTED_WITHDRAWAL === '1';

// Detached records are only a malformed-input oracle for the shared typed
// assertion. They never become business rows or establish new-use permission.
it.runIf(runtimeUrl && source)(
  'checks terminal failure receipt and effect fields without changing the original business rows',
  async () => {
    const q = z
      .strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid(), generationId: z.uuid() })
      .parse(JSON.parse(source!));
    const pool = new Pool({ connectionString: runtimeUrl, max: 1 });
    const client = await pool.connect();
    const original = `select to_jsonb(g) generation,to_jsonb(w) work
      from control.runtime_configuration_generation g join control.configuration_work w using(runtime_configuration_generation_id)
      where g.runtime_configuration_generation_id=$1`;
    const check = `select openpc.runtime_generation_retry_failure_payload(
      jsonb_populate_record(g,$2::jsonb),jsonb_populate_record(w,$3::jsonb)) payload
      from control.runtime_configuration_generation g join control.configuration_work w using(runtime_configuration_generation_id)
      where g.runtime_configuration_generation_id=$1`;
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',false)",
        [q.participantId, q.privacyDomainId, id()],
      );
      const signature =
        'openpc.runtime_generation_retry_failure_payload(control.runtime_configuration_generation,control.configuration_work)';
      expect(
        (
          await client.query(
            `select p.prosecdef,p.provolatile,
        has_function_privilege('openpc_control_reader',p.oid,'EXECUTE') reader,
        exists(select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE') public
        from pg_proc p where p.oid=$1::regprocedure`,
            [signature],
          )
        ).rows[0],
      ).toEqual({ prosecdef: false, provolatile: 's', reader: false, public: false });
      const before = await client.query(original, [q.generationId]);
      expect(before.rowCount).toBe(1);
      const receipt = before.rows[0].work.result_receipt;
      const valid = await client.query(check, [q.generationId, {}, {}]);
      expect(valid.rowCount).toBe(1);
      expect(JSON.parse(valid.rows[0].payload.toString('utf8'))).toEqual(receipt);
      const variants: Array<[Record<string, unknown>, Record<string, unknown>]> = [
        ...[
          { configuration_work_id: null },
          { participant_id: id() },
          { privacy_domain_id: id() },
          { runtime_configuration_generation_id: id() },
          { operation_id: null },
          { state: null },
          { state: 'RECONCILING' },
          { work_kind: null },
          { work_kind: 'PROVIDER_QUALIFICATION' },
          { runtime_target_id: id() },
          { resource_id: id() },
          { resource_id: null },
          { generation_digest: `sha256:${'ef'.repeat(32)}` },
          {
            predecessor_digest:
              before.rows[0].work.predecessor_digest === null ? `sha256:${'ef'.repeat(32)}` : null,
          },
          { execution_started_at: new Date().toISOString() },
          { execution_attempt_id: id() },
          { lease_owner: 'original-lease' },
          { lease_until: new Date().toISOString() },
          { reconcile_after: new Date().toISOString() },
          { completed_at: null },
          { result_event_id: null },
          { last_error_code: null },
          { last_error_code: 'PC-DATA-6007' },
          { result_receipt: null },
          { result_receipt: [] },
          { result_receipt: { ...receipt, terminal: false } },
          { result_receipt: { ...receipt, resourceId: id() } },
          { result_receipt: { ...receipt, extra: true } },
          { result_receipt_digest: null },
          { result_receipt_digest: `sha256:${'ab'.repeat(32)}` },
        ].map((work): [Record<string, unknown>, Record<string, unknown>] => [{}, work]),
        ...[
          { runtime_configuration_generation_id: null },
          { runtime_target_id: null },
          { generation_digest: null },
          { participant_id: id() },
          { privacy_domain_id: id() },
          { state: null },
          { state: 'ACTIVE' },
          { activated_at: new Date().toISOString() },
          { cigl_profile_selection: {} },
        ].map((generation): [Record<string, unknown>, Record<string, unknown>] => [generation, {}]),
      ];
      for (const [generation, work] of variants) {
        await client.query('savepoint malformed');
        await expect(client.query(check, [q.generationId, generation, work])).rejects.toMatchObject(
          { code: 'P0001', message: 'PC-DATA-6007-RUNTIME-RETRY' },
        );
        await client.query('rollback to savepoint malformed');
        await client.query('release savepoint malformed');
      }
      for (const [generation, work] of [
        ['NULL::control.runtime_configuration_generation', 'w'],
        ['g', 'NULL::control.configuration_work'],
        ['NULL::control.runtime_configuration_generation', 'NULL::control.configuration_work'],
      ]) {
        await client.query('savepoint absent');
        await expect(
          client.query(
            `select openpc.runtime_generation_retry_failure_payload(${generation},${work})
          from control.runtime_configuration_generation g join control.configuration_work w using(runtime_configuration_generation_id)
          where g.runtime_configuration_generation_id=$1`,
            [q.generationId],
          ),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007-RUNTIME-RETRY' });
        await client.query('rollback to savepoint absent');
        await client.query('release savepoint absent');
      }
      expect((await client.query(original, [q.generationId])).rows).toEqual(before.rows);
    } finally {
      await client.query('rollback');
      client.release();
      await pool.end();
    }
  },
);
// Original public terminal result supplies the lineage. All test insertions
// roll back; only the subsequent public runtime journey can establish acceptance.
it.runIf(runtimeUrl && source && !admittedWithdrawal)(
  'admits only a separate no-execution generation and excludes duplicate concurrent identities',
  async () => {
    const q = z
      .strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid(), generationId: z.uuid() })
      .parse(JSON.parse(source!));
    const pool = new Pool({ connectionString: runtimeUrl, max: 2 });
    const first = await pool.connect(),
      second = await pool.connect();
    const begin = async (
      c: PoolClient,
      privacy = q.privacyDomainId,
      action = 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
    ) => {
      await c.query('begin isolation level serializable');
      await c.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
        q.participantId,
        privacy,
        id(),
        action,
      ]);
    };
    const insert = (c: PoolClient, state = 'ACTIVATING', nullable = false) =>
      c.query(
        `insert into control.runtime_configuration_generation
    (participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,projection_plan_id,predecessor_digest,generation_digest,policy_generation_digest,state)
    select participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,projection_plan_id,
      case when $3 then null else predecessor_digest end,generation_digest,policy_generation_digest,$2
    from control.runtime_configuration_generation where runtime_configuration_generation_id=$1
    returning runtime_configuration_generation_id`,
        [q.generationId, state, nullable],
      );
    const original = `select to_jsonb(g) generation,to_jsonb(w) work from control.runtime_configuration_generation g
    join control.configuration_work w using(runtime_configuration_generation_id) where g.runtime_configuration_generation_id=$1`;
    try {
      await begin(first);
      const before = await first.query(original, [q.generationId]);
      expect(before.rowCount).toBe(1);
      expect((await insert(first)).rowCount).toBe(1);
      await begin(second);
      await expect(insert(second)).rejects.toMatchObject({
        code: '40001',
        message: 'PC-DATA-6007',
      });
      await second.query('rollback');
      await expect(insert(first)).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007-RUNTIME-RETRY',
      });
      await first.query('rollback');
      await begin(first);
      expect((await first.query(original, [q.generationId])).rows).toEqual(before.rows);
      // NULL predecessors share a single initial-content identity as well.
      expect((await insert(first, 'ACTIVATING', true)).rowCount).toBe(1);
      await expect(insert(first, 'ACTIVATING', true)).rejects.toMatchObject({
        code: '23505',
        constraint: 'runtime_configuration_generation_uq',
      });
      await first.query('rollback');
      for (const state of ['STAGED', 'ACTIVE', 'FAILED']) {
        await begin(first);
        await expect(insert(first, state)).rejects.toMatchObject({
          code: 'P0001',
          message: 'PC-DATA-6007-RUNTIME-RETRY',
        });
        await first.query('rollback');
      }
      await begin(first, q.privacyDomainId, 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1');
      await expect(insert(first)).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007-RUNTIME-RETRY',
      });
      await first.query('rollback');
      await begin(first, id());
      expect((await insert(first)).rowCount).toBe(0);
      await first.query('rollback');
      await begin(first);
      expect((await first.query(original, [q.generationId])).rows).toEqual(before.rows);
    } finally {
      await first.query('rollback');
      await second.query('rollback');
      first.release();
      second.release();
      await pool.end();
    }
  },
);

it.runIf(runtimeUrl && source && admittedWithdrawal)(
  'bounds a separate retry after acknowledged predecessor withdrawal without changing original effects',
  async () => {
    const q = z
      .strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid(), generationId: z.uuid() })
      .parse(JSON.parse(source!));
    const pool = new Pool({ connectionString: runtimeUrl, max: 1 });
    const client = await pool.connect();
    const begin = async () => {
      await client.query('begin isolation level serializable');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true)",
        [q.participantId, q.privacyDomainId, id()],
      );
    };
    const snapshot = `select to_jsonb(g) generation,to_jsonb(w) work,t.state target_state,
      t.active_generation_digest active,
      (select count(*)::int from control.runtime_activation_observation o where o.configuration_work_id=w.configuration_work_id) observations,
      (select count(*)::int from control.runtime_target_disposition_admission a
        join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
        join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
        where a.runtime_target_id=g.runtime_target_id and a.binding->'cause'->>'work_id'=w.configuration_work_id::text
          and a.binding->>'action'='Withdraw') withdrawals
      from control.runtime_configuration_generation g join control.configuration_work w using(runtime_configuration_generation_id)
      join control.runtime_target t on t.runtime_target_id=g.runtime_target_id and t.participant_id=g.participant_id and t.privacy_domain_id=g.privacy_domain_id
      where g.runtime_configuration_generation_id=$1`;
    try {
      await begin();
      expect(
        (
          await client.query(
            'select rolsuper,rolbypassrls from pg_roles where rolname=current_user',
          )
        ).rows[0],
      ).toEqual({ rolsuper: false, rolbypassrls: false });
      const before = await client.query(snapshot, [q.generationId]);
      expect(before.rowCount).toBe(1);
      const row = before.rows[0];
      expect(row.target_state).toBe('FAILED');
      expect(row.generation.state).toBe('FAILED');
      expect(row.work.state).toBe('FAILED');
      expect(row.work.execution_started_at).toBeNull();
      expect(row.work.execution_attempt_id).toBeNull();
      expect(row.work.lease_owner).toBeNull();
      expect(row.work.lease_until).toBeNull();
      expect(row.work.reconcile_after).toBeNull();
      expect(row.work.result_receipt).toEqual({
        errorCode: 'PC-RUNTIME-3001',
        resourceId: row.work.resource_id,
        terminal: true,
        workKind: 'RUNTIME_ACTIVATION',
      });
      expect(row.work.result_event_id).toMatch(/^[0-9a-f-]{36}$/u);
      expect(row.active).toBe(row.generation.predecessor_digest);
      expect(row.observations).toBe(0);
      expect(row.withdrawals).toBe(1);
      const insert = (state = 'ACTIVATING') =>
        client.query(
          `insert into control.runtime_configuration_generation
        (participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,projection_plan_id,predecessor_digest,generation_digest,policy_generation_digest,state)
        select participant_id,privacy_domain_id,runtime_target_id,provider_profile_id,projection_plan_id,predecessor_digest,generation_digest,policy_generation_digest,$2
        from control.runtime_configuration_generation where runtime_configuration_generation_id=$1
        returning runtime_configuration_generation_id,state,revision,activated_at`,
          [q.generationId, state],
        );
      // The acknowledged denial applies to the predecessor. The failed successor
      // has no execution, so the installed guard permits a distinct generation;
      // it does not create work, a delivery, an observation or serving authority.
      const created = await insert();
      expect(created.rowCount).toBe(1);
      const next = created.rows[0];
      expect(next.runtime_configuration_generation_id).not.toBe(q.generationId);
      expect(next.state).toBe('ACTIVATING');
      expect(String(next.revision)).toBe('1');
      expect(next.activated_at).toBeNull();
      expect(
        (
          await client.query(
            `select
              (select count(*)::int from control.configuration_work where runtime_configuration_generation_id=$1) work,
              (select count(*)::int from control.runtime_activation_observation where runtime_configuration_generation_id=$1) observations,
              (select count(*)::int from control.runtime_target_disposition_admission
                where runtime_target_id=$2 and binding->'source'->>'runtime_configuration_generation_id'=$1::text) admissions`,
            [next.runtime_configuration_generation_id, row.generation.runtime_target_id],
          )
        ).rows[0],
      ).toEqual({ work: 0, observations: 0, admissions: 0 });
      expect((await client.query(snapshot, [q.generationId])).rows).toEqual(before.rows);
      await expect(insert()).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007-RUNTIME-RETRY',
      });
      await client.query('rollback');
      await begin();
      expect((await client.query(snapshot, [q.generationId])).rows).toEqual(before.rows);
      await client.query('rollback');
      for (const state of ['STAGED', 'ACTIVE', 'FAILED']) {
        await begin();
        await expect(insert(state)).rejects.toMatchObject({
          code: 'P0001',
          message: 'PC-DATA-6007-RUNTIME-RETRY',
        });
        await client.query('rollback');
      }
      await begin();
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
        [q.participantId, q.privacyDomainId, id()],
      );
      await expect(insert()).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-DATA-6007-RUNTIME-RETRY',
      });
      await client.query('rollback');
      await begin();
      expect((await client.query(snapshot, [q.generationId])).rows).toEqual(before.rows);
    } finally {
      await client.query('rollback');
      client.release();
      await pool.end();
    }
  },
);
