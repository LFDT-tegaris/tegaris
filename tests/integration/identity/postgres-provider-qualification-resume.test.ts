import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const retained = process.env.OPENPC_PROVIDER_RESUME_SOURCE;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
// Retained public proposal/probe identifiers only. No business state is seeded.
// Public fresh checker approval and actual qualification run in the runtime journey.
it.runIf(retained && runtimeUrl)(
  'fences original provider qualification resume against concurrent provider writes and preserves prior effects',
  async () => {
    const q = z
      .strictObject({
        participantId: z.uuid(),
        privacyDomainId: z.uuid(),
        candidateId: z.uuid(),
        providerId: z.uuid(),
      })
      .parse(JSON.parse(retained!));
    const pool = new Pool({ connectionString: runtimeUrl, max: 2 });
    const reader = await pool.connect(),
      writer = await pool.connect();
    const begin = async (client: PoolClient, privacy = q.privacyDomainId) => {
      await client.query('begin isolation level serializable');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',true)",
        [q.participantId, privacy, id()],
      );
    };
    const proof = () =>
      reader.query('select openpc.assert_mutation_resume_no_effect($1)', [q.candidateId]);
    const original = `select to_jsonb(p) provider,
      (select count(*)::int from control.outbox_event e where e.aggregate_id=p.provider_profile_id) events,
      (select count(*)::int from control.configuration_work w where w.resource_id=p.provider_profile_id) work
      from control.provider_profile p where provider_profile_id=$1`;
    try {
      await begin(reader);
      const before = await reader.query(original, [q.providerId]);
      expect(before.rowCount).toBe(1);
      expect(before.rows[0].events).toBeGreaterThan(0);
      expect(before.rows[0].work).toBeGreaterThan(0);
      await proof();
      await begin(writer);
      await writer.query("set local lock_timeout='150ms'");
      // This is the exact row UPDATE used by the public qualification owner.
      // No-op and rollback test its exclusion without inventing qualification.
      await expect(
        writer.query(
          'update control.provider_profile set revision=revision where provider_profile_id=$1',
          [q.providerId],
        ),
      ).rejects.toMatchObject({ code: '55P03' });
      await writer.query('rollback');
      await reader.query('rollback');

      await begin(writer);
      await writer.query(
        'select provider_profile_id from control.provider_profile where provider_profile_id=$1 for update',
        [q.providerId],
      );
      await begin(reader);
      await expect(proof()).rejects.toMatchObject({ code: '40001', message: 'PC-DATA-6007' });
      await expect(reader.query('select 1')).rejects.toMatchObject({ code: '25P02' });
      await reader.query('rollback');
      await writer.query('rollback');
      await begin(reader);
      await proof();
      expect((await reader.query(original, [q.providerId])).rows).toEqual(before.rows);
      await reader.query('rollback');

      await begin(reader, id());
      await expect(proof()).rejects.toMatchObject({ code: 'P0002' });
      await reader.query('rollback');
      await begin(reader);
      const consumed = await reader.query(
        `select mutation_candidate_id from control.mutation_candidate
        where resource_id=$1 and catalog_operation_id='CFG-OP-QUALIFY-PROVIDER-PROFILE' and state='CONSUMED' limit 1`,
        [q.providerId],
      );
      expect(consumed.rowCount).toBe(1);
      await expect(
        reader.query('select openpc.assert_mutation_resume_no_effect($1)', [
          consumed.rows[0].mutation_candidate_id,
        ]),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-POLICY-2004' });
    } finally {
      await reader.query('rollback');
      await writer.query('rollback');
      reader.release();
      writer.release();
      await pool.end();
    }
  },
);
