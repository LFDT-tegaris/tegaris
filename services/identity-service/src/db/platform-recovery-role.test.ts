import { expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { platformRecoveryLeaseActions } from '../domain/platform-recovery-lease.js';
import { assertPlatformRecoveryRoles } from './platform-recovery-role.js';

function setup(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  const roles = intent.preparation.administrators.map((a) => ({
    roleId: `urn:openpc:role:${a.roleId}`,
    version: '1',
    actions: [...platformRecoveryLeaseActions],
  }));
  const registered: { action_intent_id: string; risk_class: string }[] =
    platformRecoveryLeaseActions.map((action_intent_id) => ({
      action_intent_id,
      risk_class: action_intent_id === 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ? 'HIGH' : 'LOW',
    }));
  for (const admin of intent.preparation.administrators) {
    admin.usable.administration.riskClasses = ['HIGH', 'LOW'];
    admin.grantable.administration.riskClasses = ['HIGH', 'LOW'];
  }
  for (const [i, admin] of intent.preparation.administrators.entries())
    admin.roleDigest = canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: source.enrollment.participantId,
      role: roles[i],
    });
  if (failure === 'actions') roles[0]!.actions.pop();
  if (failure === 'revision') roles[0]!.version = '2';
  const query = vi.fn(async (sql: string, values: unknown[]) =>
    sql.includes('control.action_intent')
      ? { rowCount: registered.length, rows: registered }
      : {
          rowCount: failure === 'absent' ? 0 : 1,
          rows: [
            {
              role: roles[
                intent.preparation.administrators.findIndex((a) => a.roleId === values[1])
              ],
            },
          ],
        },
  );
  const actions = [...platformRecoveryLeaseActions];
  if (failure === 'root') actions.splice(actions.indexOf('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'), 1);
  return { query, client: { query } as never, source, intent, actions, registered };
}
it('checks both exact role bindings without changing a role or installing authority', async () => {
  const v = setup();
  await assertPlatformRecoveryRoles(
    v.client,
    v.source.enrollment.participantId,
    v.intent.preparation,
    v.actions,
  );
  expect(v.query).toHaveBeenCalledTimes(3);
  expect(v.query.mock.calls.every(([sql]) => sql.startsWith('select'))).toBe(true);
  expect(v.query.mock.calls.slice(1).every(([sql]) => sql.includes('for share'))).toBe(true);
});
it.each(['actions', 'revision', 'absent', 'root'])(
  'rejects the unusable %s boundary before a timed case',
  async (failure) => {
    const v = setup(failure);
    await expect(
      assertPlatformRecoveryRoles(
        v.client,
        v.source.enrollment.participantId,
        v.intent.preparation,
        v.actions,
      ),
    ).rejects.toThrow();
  },
);

it.each([
  [0, 'usable'],
  [0, 'grantable'],
  [1, 'usable'],
  [1, 'grantable'],
] as const)(
  'rejects administrator %i with a low-only %s scope before recovery',
  async (i, scope) => {
    const v = setup();
    v.intent.preparation.administrators[i]![scope].administration.riskClasses = ['LOW'];
    await expect(
      assertPlatformRecoveryRoles(
        v.client,
        v.source.enrollment.participantId,
        v.intent.preparation,
        v.actions,
      ),
    ).rejects.toThrow('Platform recovery unavailable');
  },
);

it.each(['missing', 'duplicate', 'foreign', 'unsupported risk'])(
  'rejects an incomplete or invalid action registry: %s',
  async (failure) => {
    const v = setup();
    if (failure === 'missing') v.registered.pop();
    if (failure === 'duplicate') v.registered[1] = v.registered[0]!;
    if (failure === 'foreign')
      v.registered[0] = { ...v.registered[0]!, action_intent_id: 'ACT-UNRELATED_READ_RESOURCE-V1' };
    if (failure === 'unsupported risk') v.registered[0]!.risk_class = 'UNSUPPORTED';
    await expect(
      assertPlatformRecoveryRoles(
        v.client,
        v.source.enrollment.participantId,
        v.intent.preparation,
        v.actions,
      ),
    ).rejects.toThrow('Platform recovery unavailable');
  },
);
