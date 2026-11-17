import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { mutationResumeGuardsSql } from '../../../services/identity-service/src/db/mutation-resume-guards.mjs';

const retained = process.env.OPENPC_RUNTIME_PROFILE_RESUME_SOURCE;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;

// Use the original public proposal. This test creates no binding or approval.
it.runIf(retained && runtimeUrl)(
  'fences an unexecuted runtime profile request and preserves its original records',
  async () => {
    const q = z
      .strictObject({
        participantId: z.uuid(),
        privacyDomainId: z.uuid(),
        candidateId: z.uuid(),
        targetId: z.uuid(),
        consumedCandidateId: z.uuid(),
        expectation: z.enum(['CURRENT', 'STALE']),
      })
      .parse(JSON.parse(retained!));
    const pool = new Pool({ connectionString: runtimeUrl, max: 2 });
    const reader = await pool.connect();
    const writer = await pool.connect();
    const begin = async (client: PoolClient, privacy = q.privacyDomainId) => {
      await client.query('begin isolation level serializable');
      if (process.env.OPENPC_RUNTIME_PROFILE_RESUME_GUARD_ROLLBACK === '1') {
        // The owner connection installs this function only in its uncommitted
        // test transaction. Other sessions retain the installed definition.
        if (client === reader)
          await client.query(mutationResumeGuardsSql.split('-- This local no-effect boundary')[0]!);
        await client.query('set local role openpc_control_runtime');
      }
      expect((await client.query('select current_user as role')).rows[0].role).toBe(
        'openpc_control_runtime',
      );
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',true)",
        [q.participantId, privacy, id()],
      );
    };
    const proof = () =>
      reader.query('select openpc.assert_mutation_resume_no_effect($1)', [q.candidateId]);
    const snapshot = async () => {
      const result = await reader.query(
        `select to_jsonb(c) candidate,to_jsonb(t) target,
          (select count(*)::int from control.runtime_target_profile_binding b
           where b.runtime_target_id=t.runtime_target_id) bindings
         from control.mutation_candidate c join control.runtime_target t
          on t.participant_id=c.participant_id and t.privacy_domain_id=c.privacy_domain_id
         where c.mutation_candidate_id=$1 and t.runtime_target_id=$2`,
        [q.candidateId, q.targetId],
      );
      expect(result.rowCount).toBe(1);
      expect(result.rows[0].bindings).toBe(0);
      expect(result.rows[0].candidate.consumed_operation_id).toBeNull();
      expect(result.rows[0].candidate.catalog_operation_id).toBe(
        'CFG-OP-CREATE-RUNTIME-TARGET-PROFILE',
      );
      return result.rows;
    };
    try {
      await begin(reader);
      const before = await snapshot();
      const currentRevision = String(before[0].target.revision);
      const reviewedRevision = before[0].candidate.candidate_document.targetRevision;
      if (q.expectation === 'STALE') {
        expect(currentRevision).not.toBe(reviewedRevision);
        await expect(proof()).rejects.toMatchObject({ code: 'P0001', message: 'PC-POLICY-2004' });
        await reader.query('rollback');
        await begin(reader, id());
        await expect(proof()).rejects.toMatchObject({ code: 'P0002' });
        await reader.query('rollback');
        await begin(reader);
        await expect(
          reader.query('select openpc.assert_mutation_resume_no_effect($1)', [
            q.consumedCandidateId,
          ]),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-POLICY-2004' });
        await reader.query('rollback');
        await begin(reader);
        expect(await snapshot()).toEqual(before);
        await reader.query('rollback');
        return;
      }
      expect(currentRevision).toBe(reviewedRevision);
      await proof();
      await begin(writer);
      await writer.query("set local lock_timeout='150ms'");
      await expect(
        writer.query(
          'select runtime_target_id from control.runtime_target where runtime_target_id=$1 for update',
          [q.targetId],
        ),
      ).rejects.toMatchObject({ code: '55P03' });
      await writer.query('rollback');
      await reader.query('rollback');

      await begin(writer);
      await writer.query(
        'select runtime_target_id from control.runtime_target where runtime_target_id=$1 for update',
        [q.targetId],
      );
      await begin(reader);
      await expect(proof()).rejects.toMatchObject({ code: '40001', message: 'PC-DATA-6007' });
      await reader.query('rollback');
      await writer.query('rollback');

      await begin(reader, id());
      await expect(proof()).rejects.toMatchObject({ code: 'P0002' });
      await reader.query('rollback');

      await begin(reader);
      await expect(
        reader.query('select openpc.assert_mutation_resume_no_effect($1)', [q.consumedCandidateId]),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-POLICY-2004' });
      await reader.query('rollback');

      await begin(reader);
      await proof();
      expect(await snapshot()).toEqual(before);
      await reader.query('rollback');
    } finally {
      await reader.query('rollback');
      await writer.query('rollback');
      reader.release();
      writer.release();
      await pool.end();
    }
  },
);
