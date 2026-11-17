import assert from 'node:assert/strict';
import test from 'node:test';
import { Pool } from 'pg';
import { seedQa, qaParticipants } from './qa-sandbox.mjs';

test(
  'explicit QA fixture initializes empty installation only and preserves tenant isolation without business effects',
  { skip: !process.env.OPENPC_I02_ADMIN_DATABASE_URL },
  async () => {
    const pool = new Pool({ connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL });
    const client = await pool.connect();
    try {
      await seedQa(client);
      assert.equal(
        (await client.query('select count(*)::int n from control.participant')).rows[0].n,
        2,
      );
      assert.equal(
        (
          await client.query(
            "select count(*)::int n from control.principal where kind='PLATFORM_OPERATOR' and state='ACTIVE'",
          )
        ).rows[0].n,
        4,
      );
      for (const table of [
        'policy',
        'policy_version',
        'policy_activation',
        'mutation_candidate',
        'approval_request',
        'mutation_evidence',
        'outbox_event',
        'session',
        'platform_context',
      ])
        assert.equal(
          (await client.query(`select count(*)::int n from control.${table}`)).rows[0].n,
          0,
          table,
        );
      assert.equal(
        (await client.query("select count(*)::int n from control.credential where kind='WEBAUTHN'"))
          .rows[0].n,
        0,
      );
      const original = (
        await client.query(
          'select jsonb_agg(to_jsonb(a) order by assignment_id) data from control.assignment a',
        )
      ).rows[0].data;
      await assert.rejects(seedQa(client), /empty installation/u);
      assert.deepEqual(
        (
          await client.query(
            'select jsonb_agg(to_jsonb(a) order by assignment_id) data from control.assignment a',
          )
        ).rows[0].data,
        original,
      );
      const runtime = new Pool({ connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL });
      const connection = await runtime.connect();
      try {
        await connection.query('begin');
        await connection.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,'018f0000-0000-7000-8000-000000009999','ACT-PARTICIPANTS_READ_RESOURCE-V1',true)",
          [qaParticipants[0].participantId, qaParticipants[0].privacyDomainId],
        );
        const rows = await connection.query('select participant_id from control.assignment');
        assert.equal(rows.rowCount, 2);
        assert.ok(rows.rows.every((row) => row.participant_id === qaParticipants[0].participantId));
        await connection.query('rollback');
      } finally {
        connection.release();
        await runtime.end();
      }
    } finally {
      client.release();
      await pool.end();
    }
  },
);
