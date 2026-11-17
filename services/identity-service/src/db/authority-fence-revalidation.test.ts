import { expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  revalidateBoundAuthorities,
  revalidateDurableAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from './authority-fence.js';
vi.mock('../domain/recovery-principal.js', () => ({ assertRecoveryPrincipalAction: vi.fn() }));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const authority: BoundAuthority = {
  principalId: id(3),
  sessionId: id(4),
  sessionEpoch: '1',
  participantEpoch: '1',
  principalEpoch: '1',
  assignmentId: id(5),
  assignmentRowVersion: '1',
  authorityEnvelopeId: id(6),
  authorityEpoch: '1',
  delegationEpoch: '0',
  privacyDomainId: id(2),
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  resourceId: id(7),
};
const held: AuthorityFence = {
  participant: [{ id: id(1) }],
  privacy_domain: [{ id: id(2) }],
  principal: [{ id: id(3) }],
  session: [{ id: id(4) }],
  assignment: [{ id: id(5) }],
  authority_envelope: [{ id: id(6) }],
  authority_role: [{ id: id(8) }],
};
const path = { principalIds: [id(3)], delegationIds: [], roleId: id(8) };
it('revalidates exact current authority through its real owner without acquiring another lock', async () => {
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [path] });
  await revalidateBoundAuthorities({ query } as unknown as PoolClient, id(1), [authority], held);
  expect(query).toHaveBeenCalledOnce();
  const [sql, parameters] = query.mock.calls[0]!;
  expect(sql).toContain('clock_timestamp()');
  expect(sql).not.toMatch(/for (share|update)/iu);
  expect(parameters).toContain(authority.actionIntentId);
  expect(parameters).toContain(authority.resourceId);
  expect(parameters).toContain(authority.sessionId);
});
it('rechecks durable grant time/path/epochs under original locks without requiring its old browser session', async () => {
  const grant = Object.fromEntries(
    Object.entries(authority).filter(([key]) => key !== 'sessionId' && key !== 'sessionEpoch'),
  ) as Omit<BoundAuthority, 'sessionId' | 'sessionEpoch'>;
  const dependencies = {
    path,
    principals: [[id(3), '1']],
    privacy: '1',
    role: '1',
    delegations: null,
  };
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [path] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ dependencies }] });
  await revalidateDurableAuthorities({ query } as unknown as PoolClient, id(1), [
    { grant, dependencies },
  ]);
  expect(query.mock.calls[0]![0]).toContain('clock_timestamp()');
  for (const [sql] of query.mock.calls)
    expect(sql).not.toMatch(/for share|for update|control.session/iu);
});
it('rejects changed durable path dependencies and expired original grants rather than locking a successor', async () => {
  const grant = Object.fromEntries(
    Object.entries(authority).filter(([key]) => key !== 'sessionId' && key !== 'sessionEpoch'),
  ) as Omit<BoundAuthority, 'sessionId' | 'sessionEpoch'>;
  for (const expired of [true, false]) {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rowCount: expired ? 0 : 1, rows: expired ? [] : [path] })
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [{ dependencies: { path: { ...path, principalIds: [id(99)] } } }],
      });
    await expect(
      revalidateDurableAuthorities({ query } as unknown as PoolClient, id(1), [
        { grant, dependencies: { path } },
      ]),
    ).rejects.toThrow();
    for (const [sql] of query.mock.calls) expect(sql).not.toMatch(/for share|for update/iu);
  }
});
it('denies expired or unavailable authority and an ambiguous current path', async () => {
  for (const rowCount of [0, 2]) {
    const query = vi.fn().mockResolvedValue({ rowCount, rows: rowCount === 0 ? [] : [path, path] });
    await expect(
      revalidateBoundAuthorities({ query } as unknown as PoolClient, id(1), [authority], held),
    ).rejects.toThrow();
  }
});
it.each([
  { ...path, principalIds: [id(3), id(20)] },
  { ...path, delegationIds: [id(21)] },
  { ...path, roleId: id(22) },
])('denies a newly discovered unheld parent instead of taking a late lock', async (next) => {
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [next] });
  await expect(
    revalidateBoundAuthorities({ query } as unknown as PoolClient, id(1), [authority], held),
  ).rejects.toThrow();
  expect(query).toHaveBeenCalledOnce();
});
it('rejects empty authority and missing original participant/privacy/session/aggregate parents', async () => {
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [path] }),
    client = { query } as unknown as PoolClient;
  await expect(revalidateBoundAuthorities(client, id(1), [], held)).rejects.toThrow();
  expect(query).not.toHaveBeenCalled();
  for (const table of [
    'participant',
    'privacy_domain',
    'session',
    'authority_envelope',
    'assignment',
  ] as const)
    await expect(
      revalidateBoundAuthorities(client, id(1), [authority], { ...held, [table]: [] }),
    ).rejects.toThrow();
});
