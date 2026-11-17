import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { fenceEnvelopePlatformContext } from '../../../services/identity-service/src/db/platform-context.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl === undefined || runtimeUrl === undefined ? it.skip : it;

integration('rejects missing recovery history within bounded Owner queries', async () => {
  const pool = new Pool({ connectionString: adminUrl, max: 1 });
  let client: PoolClient | undefined;
  const failures: unknown[] = [];
  const participantId = id();
  try {
    client = await pool.connect();
    await client.query('begin isolation level read committed read only');
    await client.query("set local statement_timeout='2s'");
    await client.query("set local lock_timeout='500ms'");
    await client.query('set local role openpc_control_owner');
    await client.query('set local row_security=on');
    expect(
      (
        await client.query(`select current_user as name,rolsuper,rolbypassrls
          from pg_roles where rolname=current_user`)
      ).rows,
    ).toEqual([{ name: 'openpc_control_owner', rolsuper: false, rolbypassrls: false }]);
    await client.query(
      `select set_config('openpc.context_mode','PARTICIPANT',true),
        set_config('openpc.context_scope','TRANSACTION_LOCAL',true),
        set_config('openpc.participant_id',$1,true),
        set_config('openpc.privacy_domain_id',$2,true),
        set_config('openpc.operation_id',$3,true),
        set_config('openpc.action_intent_id','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',true),
        set_config('openpc.local_qa_runtime','1',true)`,
      [participantId, id(), id()],
    );
    // Distinct missing enrollments exercise repeated calls without seeding trust,
    // approvals or business records. The previous combined plan exhausted 1 GiB.
    for (let attempt = 0; attempt < 8; attempt++) {
      const result = await client.query<{ current: boolean }>(
        `select openpc.platform_recovery_pending_expiry_source_current(
          $1::uuid,$2::uuid,'{}'::jsonb,'{}'::jsonb) as current`,
        [participantId, id()],
      );
      expect(result.rows).toEqual([{ current: false }]);
      const absentSource = await client.query<{ installation: boolean; root: boolean }>(
        `select openpc.root_expiry_recovery_installation_source_current($1::uuid) as installation,
          openpc.platform_recovery_source_root_current(null::control.platform_recovery_enrollment) as root`,
        [id()],
      );
      expect(absentSource.rows).toEqual([{ installation: false, root: false }]);
    }
  } catch (error) {
    failures.push(error);
  } finally {
    if (client) {
      try {
        await client.query('rollback');
      } catch (error) {
        failures.push(error);
      }
      try {
        client.release();
      } catch (error) {
        failures.push(error);
      }
    }
    try {
      await pool.end();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) throw new AggregateError(failures, 'Pending-expiry regression failed');
});

// Initial trust fixtures exercise the installed custody owner, not public
// Platform lifecycle acceptance. Public issuance is covered by first-admin.
integration(
  'keeps explicit Platform custody immutable, scoped and independent across upgrades',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const participant = id(),
      foreign = id(),
      principal = id(),
      platform = id();
    const bound = id(),
      unbound = id(),
      stale = id();
    const scoped = <T>(operation: (client: PoolClient) => Promise<T>, tenant = participant) =>
      runScopedTransaction(
        runtime,
        { participantId: tenant, actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
        id,
        operation,
      );
    try {
      for (const tenant of [participant, foreign])
        await admin.query(
          `insert into control.participant(participant_id,display_name,state,authority_epoch)
        values($1,'Platform custody initial trust','ACTIVE',1)`,
          [tenant],
        );
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'PLATFORM_OPERATOR','Platform custodian','ACTIVE',1)`,
        [principal, participant],
      );
      await admin.query(
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
      values($1,$2,'ACTIVE',13,1)`,
        [platform, participant],
      );
      for (const [envelope, epoch] of [
        [bound, '13'],
        [unbound, null],
        [stale, '12'],
      ] as const) {
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,
        authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,
        action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,
        platform_context_id,platform_authority_epoch)
        values($1,$2,$3,$3,1,2,'ACTIVE',clock_timestamp()-interval '1 minute',$4,$5,$4,ARRAY[]::text[],
          ARRAY['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],ARRAY['*'],ARRAY['STANDARD'],false,false,0,$6,$7)`,
          [
            envelope,
            participant,
            principal,
            Buffer.from([0x80]),
            createHash('sha256').update(envelope).digest(),
            epoch === null ? null : platform,
            epoch,
          ],
        );
      }
      const current = () => scoped((c) => fenceEnvelopePlatformContext(c, participant, bound));
      expect(await current()).toEqual({
        platformContextId: platform,
        platformAuthorityEpoch: '13',
      });
      expect(await scoped((c) => fenceEnvelopePlatformContext(c, participant, unbound))).toBeNull();
      await expect(
        scoped((c) => fenceEnvelopePlatformContext(c, participant, stale)),
      ).rejects.toThrow('authority dependency');
      await scoped(async (c) => {
        expect((await c.query('select * from control.platform_context')).rowCount).toBe(0);
        expect(
          (
            await c.query('select * from openpc.lock_authority_envelope_platform_context($1)', [
              bound,
            ])
          ).rowCount,
        ).toBe(0);
      }, foreign);
      for (const sql of [
        'update control.platform_context set authority_epoch=14,row_version=2,updated_at=clock_timestamp()',
        'delete from control.platform_context',
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
       values('${id()}','${participant}','ACTIVE',1,1)`,
      ])
        await expect(scoped((c) => c.query(sql))).rejects.toMatchObject({ code: '42501' });
      for (const epoch of [null, '13'])
        await expect(
          admin.query(
            'update control.authority_envelope set platform_context_id=$1,platform_authority_epoch=$2 where authority_envelope_id=$3',
            [epoch === null ? null : platform, epoch, epoch === null ? bound : unbound],
          ),
        ).rejects.toThrow('PLATFORM-CONTEXT');
      await expect(
        admin.query(
          'update control.platform_context set authority_epoch=12,row_version=2,updated_at=clock_timestamp() where platform_context_id=$1',
          [platform],
        ),
      ).rejects.toThrow('PLATFORM-CONTEXT');

      // Reapply the generated security projection with populated identity and
      // independently installed Control owners. Their grants must survive.
      const sourcePermission = () =>
        admin.query(`select has_function_privilege('openpc_control_reader',
      'openpc.lock_fact_candidate_source(uuid)','EXECUTE') as allowed`);
      expect((await sourcePermission()).rows).toEqual([{ allowed: true }]);
      const migration = await readFile(
        new URL('../../../migrations/postgres/identity/0056_blue_inertia.sql', import.meta.url),
        'utf8',
      );
      const marker = '-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT';
      expect(migration.includes(marker)).toBe(true);
      await admin.query(migration.slice(migration.indexOf(marker)));
      expect((await sourcePermission()).rows).toEqual([{ allowed: true }]);
      expect(await current()).toEqual({
        platformContextId: platform,
        platformAuthorityEpoch: '13',
      });

      await admin.query(
        `update control.platform_context set state='SUSPENDED',authority_epoch=14,
      row_version=2,updated_at=clock_timestamp() where platform_context_id=$1`,
        [platform],
      );
      await expect(current()).rejects.toThrow('authority dependency');
      await admin.query(
        `update control.platform_context set state='ACTIVE',authority_epoch=15,
      row_version=3,updated_at=clock_timestamp() where platform_context_id=$1`,
        [platform],
      );
      // Recovery cannot revive an old envelope, even with the original state.
      await expect(current()).rejects.toThrow('authority dependency');
      await admin.query(
        `update control.platform_context set state='RETIRED',authority_epoch=16,
      row_version=4,updated_at=clock_timestamp() where platform_context_id=$1`,
        [platform],
      );
      await expect(
        admin.query(
          `update control.platform_context set state='ACTIVE',authority_epoch=17,
      row_version=5,updated_at=clock_timestamp() where platform_context_id=$1`,
          [platform],
        ),
      ).rejects.toThrow('PLATFORM-CONTEXT');
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
  30000,
);
