import { expect } from 'vitest';
import type { Pool } from 'pg';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

/** Component check of the real lock helper and FORCE RLS, using actual issued
 * authority rows. The temporary trigger creates no intermediate business state;
 * reservation, consumption and send acceptance still belong to the runtime. */
export async function assertNativeValueAuthorityLocks(
  admin: Pool,
  participantId: string,
  privacyDomainId: string,
  walletId: string,
  principalId: string,
) {
  const locker = await admin.connect();
  const contender = await admin.connect();
  try {
    await locker.query(`
      create temporary table native_lock_probe(wallet_id uuid,actor_id uuid);
      grant insert on native_lock_probe to openpc_control_worker;
      create function pg_temp.native_lock_probe() returns trigger language plpgsql security invoker as $$
      begin
        perform openpc.lock_native_value_authority(NEW.wallet_id,NEW.actor_id);
        return NEW;
      end $$;
      create trigger lock_probe before insert on native_lock_probe
        for each row execute function pg_temp.native_lock_probe();
    `);
    const begin = async (selectedParticipant = participantId) => {
      await locker.query('begin');
      await locker.query('set local role openpc_control_worker');
      await locker.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
          'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true)`,
        [selectedParticipant, privacyDomainId, id()],
      );
    };
    await begin();
    await locker.query('savepoint direct_call');
    await expect(
      locker.query('select openpc.lock_native_value_authority($1,$2)', [walletId, principalId]),
    ).rejects.toMatchObject({ code: 'P0001' });
    await locker.query('rollback to savepoint direct_call');
    await locker.query('insert into native_lock_probe values($1,$2)', [walletId, principalId]);
    for (const [table, column, value] of [
      ['wallet_binding', 'wallet_binding_id', walletId],
      ['participant', 'participant_id', participantId],
      ['principal', 'principal_id', principalId],
      ['credential', 'principal_id', principalId],
    ]) {
      // NOWAIT is an independent physical-lock oracle. No business update is
      // performed and a missing lock fails immediately instead of timing out.
      await expect(
        contender.query(`select 1 from control.${table} where ${column}=$1 for update nowait`, [
          value,
        ]),
      ).rejects.toMatchObject({ code: '55P03' });
    }
    await locker.query('rollback');
    await begin(id());
    await expect(
      locker.query('insert into native_lock_probe values($1,$2)', [walletId, principalId]),
    ).rejects.toMatchObject({ code: 'P0001' });
    await locker.query('rollback');
    // The definer gains no general visibility outside the guarded trigger.
    await locker.query('begin');
    await locker.query('set local role openpc_control_owner');
    // Wallet access is trigger-only; identity policies additionally require a context.
    expect(
      (await locker.query('select count(*)::int n from control.wallet_binding')).rows[0].n,
    ).toBe(0);
    for (const table of ['principal', 'credential']) {
      await locker.query('savepoint missing_context');
      await expect(
        locker.query(`select count(*)::int n from control.${table}`),
      ).rejects.toMatchObject({
        code: 'P0001',
        message: 'DATA-6001-CONTEXT-INVALID',
      });
      await locker.query('rollback to savepoint missing_context');
    }
  } finally {
    await locker.query('rollback');
    locker.release(true);
    contender.release();
  }
}
