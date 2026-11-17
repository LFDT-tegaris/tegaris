import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { z } from 'zod';

const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = runtimeUrl && workerUrl ? it : it.skip;
const retainedInput = process.env.OPENPC_RUNTIME_ARTIFACT_FENCE_SOURCE;
// Independent inventory of actual reference producers, including historical
// recovery owners. Empty statements exercise the installed BEFORE STATEMENT
// boundary without inventing approval, activation or completion business state.
const producers = [
  'runtime_configuration_input',
  'configuration_work',
  'runtime_configuration_generation',
  'runtime_target',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'runtime_activation_observation',
  'runtime_target_connection',
  'runtime_route_publication',
  'provider_probe_observation',
  'runtime_target_disposition_admission',
  'runtime_target_disposition_delivery',
  'runtime_target_disposition_acknowledgement',
  'module_configuration_generation',
  'module_installation',
  'policy_activation',
  'policy_activation_prerequisite',
  'policy_generation',
  'provider_profile',
  'indexer_profile',
  'cigl_settings',
  'projection_plan',
] as const;

async function begin(client: PoolClient, participant: string, privacy: string, operationId = id()) {
  await client.query('begin');
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)`,
    [participant, privacy, operationId],
  );
  await client.query("set local statement_timeout='2s'");
}

integration(
  'serializes every runtime artifact reference producer with disposition without granting clearance',
  async () => {
    const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const clients: PoolClient[] = [];
    try {
      const holder = await runtime.connect();
      clients.push(holder);
      const runtimeWriter = await runtime.connect();
      clients.push(runtimeWriter);
      const workerWriter = await worker.connect();
      clients.push(workerWriter);
      for (const client of clients) {
        const role = await client.query(
          'select not rolsuper and not rolbypassrls safe from pg_roles where rolname=current_user',
        );
        expect(role.rows[0]?.safe).toBe(true);
      }
      const participant = id(),
        privacy = id();
      // The same contention has distinct established API/native contracts.
      // Exercise both public new-use admission and the serializable row-lock
      // owner so neither sibling can turn retryable contention into UNKNOWN.
      for (const [isolation, admission, code] of [
        ['read committed', 'runtime_artifact_new_use_allowed', 'P0001'],
        ['serializable', 'runtime_artifact_new_use_allowed', '40001'],
        ['serializable', 'lock_runtime_artifact_originals', '40001'],
      ]) {
        const operationId = id();
        await begin(holder, participant, privacy);
        await lockEvidenceLifecycle(holder, participant, privacy);
        const attempt = async () => {
          await runtimeWriter.query(`begin isolation level ${isolation}`);
          await runtimeWriter.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
            [participant, privacy, operationId],
          );
          return runtimeWriter.query(`select openpc.${admission}($1,$2,$3) allowed`, [
            participant,
            privacy,
            Buffer.alloc(32, 9),
          ]);
        };
        await expect(attempt()).rejects.toMatchObject({ code, message: 'PC-DATA-6007' });
        await expect(runtimeWriter.query('select 1')).rejects.toMatchObject({ code: '25P02' });
        await runtimeWriter.query('rollback');
        await holder.query('rollback');
        const retried = await attempt();
        expect(retried.rowCount).toBe(1);
        if (admission === 'runtime_artifact_new_use_allowed') {
          expect(retried.rows[0]?.allowed).toBe(true);
        }
        expect(
          (await runtimeWriter.query('select openpc.current_operation_id()::text operation'))
            .rows[0]?.operation,
        ).toBe(operationId);
        await runtimeWriter.query('rollback');
      }
      // The governed API uses SERIALIZABLE, while native execution uses READ
      // COMMITTED. Both must retain the actual lifecycle lock without granting
      // callers UPDATE access merely to lock original rows. No original input
      // or business effect is fabricated by these admission-boundary cases.
      for (const isolation of ['read committed', 'serializable']) {
        await runtimeWriter.query(`begin isolation level ${isolation}`);
        await runtimeWriter.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
          [participant, privacy, id()],
        );
        expect(
          (
            await runtimeWriter.query(
              'select openpc.runtime_artifact_new_use_allowed($1,$2,$3) allowed',
              [participant, privacy, Buffer.alloc(32, 9)],
            )
          ).rows[0]?.allowed,
        ).toBe(true);
        expect(
          (
            await runtimeWriter.query(
              "select has_table_privilege(current_user,'control.runtime_configuration_input','UPDATE') allowed",
            )
          ).rows[0]?.allowed,
        ).toBe(false);
        await begin(holder, participant, privacy);
        expect(
          (
            await holder.query(
              'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
              [`evidence-lifecycle:${participant}`],
            )
          ).rows[0]?.acquired,
        ).toBe(false);
        await holder.query('rollback');
        await runtimeWriter.query('rollback');
      }
      for (const isolation of ['serializable', 'repeatable read']) {
        await runtimeWriter.query(`begin isolation level ${isolation}`);
        await runtimeWriter.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
          [participant, privacy, id()],
        );
        await expect(
          runtimeWriter.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3)', [
            isolation === 'serializable' ? id() : participant,
            privacy,
            Buffer.alloc(32, 9),
          ]),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-AUTH-0005' });
        await runtimeWriter.query('rollback');
      }
      const inventory = await holder.query<{
        table_name: string;
        tgtype: number;
        tgenabled: string;
      }>(
        `select c.relname table_name,t.tgtype,t.tgenabled from pg_trigger t
       join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace
       join pg_proc p on p.oid=t.tgfoid join pg_namespace pn on pn.oid=p.pronamespace
       where n.nspname='control' and t.tgname='artifact_lifecycle_fence'
        and pn.nspname='openpc' and p.proname='guard_runtime_artifact_lifecycle_fence'
        and not t.tgisinternal order by c.relname`,
      );
      expect(inventory.rows.map((row) => row.table_name)).toEqual([...producers].sort());
      expect(inventory.rows.every((row) => row.tgtype === 62 && row.tgenabled === 'O')).toBe(true);

      for (const table of producers) {
        const tableName = `control.${table}`;
        const grants = await Promise.all(
          [runtimeWriter, workerWriter].map(async (client) => {
            const result = await client.query(
              "select has_table_privilege(current_user,$1,'INSERT') allowed",
              [tableName],
            );
            return result.rows[0]?.allowed === true;
          }),
        );
        const producer = grants[1] ? workerWriter : grants[0] ? runtimeWriter : undefined;
        if (table.startsWith('runtime_target_disposition_')) {
          // These producers are exclusively SECURITY DEFINER admissions. Their
          // public roles must not gain raw DML merely to exercise this corpus.
          // Installed fence identity is checked above; exact native capability
          // and direct-SQL denial are exercised by the disposition owner case.
          expect(producer).toBeUndefined();
          continue;
        }
        expect(producer, `${table} needs an actual non-bypass producer`).toBeDefined();
        if (!producer) throw new Error('Missing runtime artifact producer');
        const columns = await producer.query<{ name: string; type: string }>(
          `select quote_ident(attname) name,format_type(atttypid,atttypmod) type from pg_attribute where attrelid=$1::regclass
         and attnum>0 and not attisdropped and attgenerated='' and attidentity<>'a' order by attnum`,
          [tableName],
        );
        const names = columns.rows.map((column) => column.name).join(',');
        // Some native producers may insert but cannot read protected originals.
        // A typed empty projection reaches the statement guard with those
        // actual grants and never creates or reads a business row.
        const values = columns.rows.map((column) => `null::${column.type}`).join(',');
        const mutation = `insert into ${tableName} (${names}) select ${values} where false`;
        await begin(holder, participant, privacy);
        await lockEvidenceLifecycle(holder, participant, privacy);
        // Privacy changes cannot evade a Participant-wide hold/disposition fence.
        const producerPrivacy = id(),
          operationId = id();
        await begin(producer, participant, producerPrivacy, operationId);
        await expect(producer.query(mutation)).rejects.toMatchObject({
          code: '40001',
          message: 'PC-DATA-6007',
        });
        // The failed statement cannot be followed by a commit of partial work.
        await expect(producer.query('select 1')).rejects.toMatchObject({ code: '25P02' });
        await producer.query('rollback');
        // Unrelated Participants remain independent.
        await begin(producer, id(), id());
        expect((await producer.query(mutation)).rowCount).toBe(0);
        await producer.query('rollback');
        await holder.query('rollback');

        await begin(producer, participant, producerPrivacy, operationId);
        expect(
          (await producer.query('select openpc.current_operation_id()::text operation')).rows[0]
            ?.operation,
        ).toBe(operationId);
        expect((await producer.query(mutation)).rowCount).toBe(0);
        // Its subsequent evidence publication is reentrant, not a lock upgrade.
        await lockEvidenceLifecycle(producer, participant, privacy);
        await begin(holder, participant, privacy);
        const contested = await holder.query(
          'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
          [`evidence-lifecycle:${participant}`],
        );
        expect(contested.rows[0]?.acquired).toBe(false);
        await producer.query('rollback');
        const released = await holder.query(
          'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
          [`evidence-lifecycle:${participant}`],
        );
        expect(released.rows[0]?.acquired).toBe(true);
        await holder.query('rollback');
      }
    } finally {
      for (const client of clients) {
        await client.query('rollback');
        client.release();
      }
      await Promise.all([runtime.end(), worker.end()]);
    }
  },
);

// A retained public source supplies identifiers only. The concurrent update is
// a no-op through the existing worker role: every original business column is
// verified unchanged. Its new MVCC tuple deterministically exercises the same
// stale-snapshot rejection that a changed/deleted original must cause. This is
// a SQL concurrency regression, not physical-retirement acceptance.
it.runIf(runtimeUrl && workerUrl && retainedInput)(
  'rejects a serializable snapshot predating an original input tuple and preserves its contents',
  async () => {
    const q = z
      .strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid(), inputId: z.uuid() })
      .parse(JSON.parse(retainedInput!));
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const reader = await runtime.connect();
    const writer = await worker.connect();
    try {
      await begin(writer, q.participantId, q.privacyDomainId);
      const read =
        'select to_jsonb(i) original,configuration_digest from control.runtime_configuration_input i where runtime_configuration_input_id=$1';
      const before = await writer.query(read, [q.inputId]);
      expect(before.rowCount).toBe(1);
      await writer.query('rollback');
      const operationId = id();
      await begin(writer, q.participantId, q.privacyDomainId);
      await writer.query(
        'select runtime_configuration_input_id from control.runtime_configuration_input where runtime_configuration_input_id=$1 for update',
        [q.inputId],
      );
      const admitOriginal = async () => {
        await reader.query('begin isolation level serializable');
        await reader.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
          [q.participantId, q.privacyDomainId, operationId],
        );
        return reader.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3) allowed', [
          q.participantId,
          q.privacyDomainId,
          before.rows[0].configuration_digest,
        ]);
      };
      await expect(admitOriginal()).rejects.toMatchObject({
        code: '40001',
        message: 'PC-DATA-6007',
      });
      await expect(reader.query('select 1')).rejects.toMatchObject({ code: '25P02' });
      await reader.query('rollback');
      await writer.query('rollback');
      expect((await admitOriginal()).rows[0]?.allowed).toBe(true);
      expect((await reader.query(read, [q.inputId])).rows).toEqual(before.rows);
      expect(
        (await reader.query('select openpc.current_operation_id()::text operation')).rows[0]
          ?.operation,
      ).toBe(operationId);
      await reader.query('rollback');
      await reader.query('begin isolation level serializable');
      await reader.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',true)",
        [q.participantId, q.privacyDomainId, id()],
      );
      expect((await reader.query(read, [q.inputId])).rows).toEqual(before.rows);
      await begin(writer, q.participantId, q.privacyDomainId);
      expect(
        (
          await writer.query(
            'update control.runtime_configuration_input set selected=selected where runtime_configuration_input_id=$1',
            [q.inputId],
          )
        ).rowCount,
      ).toBe(1);
      await writer.query('commit');
      await expect(
        reader.query('select openpc.runtime_artifact_new_use_allowed($1,$2,$3)', [
          q.participantId,
          q.privacyDomainId,
          before.rows[0].configuration_digest,
        ]),
      ).rejects.toMatchObject({ code: '40001' });
      await reader.query('rollback');
      await begin(writer, q.participantId, q.privacyDomainId);
      expect((await writer.query(read, [q.inputId])).rows).toEqual(before.rows);
      await writer.query('rollback');
    } finally {
      await reader.query('rollback');
      await writer.query('rollback');
      reader.release();
      writer.release();
      await Promise.all([runtime.end(), worker.end()]);
    }
  },
);
