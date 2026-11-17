import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigest } from '../../../identity-service/src/contracts/authorization.js';
import { readRoleBindingPreview } from './role-binding-preview.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const roleId = '018f0000-0000-7000-8000-000000000501';
const role = {
  roleId: `urn:openpc:role:${roleId}`,
  version: '3',
  actions: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
  origin: 'BOOTSTRAP',
  createdByPrincipalId: '018f0000-0000-7000-8000-000000000111',
  creatorParticipantId: participantId,
  bootstrapMandateId: '018f0000-0000-7000-8000-000000000601',
  bootstrapPlatformParticipantId: participantId,
};

describe('authoritative role binding preview with a mocked database', () => {
  it('binds full role provenance without disclosing that provenance or creating authority', async () => {
    const query = vi.fn<
      (
        sql: string,
        values: string[],
      ) => Promise<{ rowCount: number; rows: { role: typeof role }[] }>
    >(async () => ({ rowCount: 1, rows: [{ role }] }));
    const result = await readRoleBindingPreview(
      { query } as unknown as PoolClient,
      participantId,
      roleId,
    );
    expect(result).toEqual({
      participantId,
      roleId,
      roleRef: role.roleId,
      revision: '3',
      actionIntentIds: role.actions,
      roleDigest: canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId,
        role,
      }),
    });
    expect(result).not.toHaveProperty('bootstrapMandateId');
    expect(query).toHaveBeenCalledWith(expect.stringContaining("role.state='ACTIVE' for share"), [
      participantId,
      roleId,
    ]);
    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0]?.[0]).not.toMatch(/insert|update|delete/iu);
  });

  it.each([0, 2])('hides missing or ambiguous role binding (cardinality %i)', async (rowCount) => {
    const query = vi.fn(async () => ({ rowCount, rows: rowCount ? [{ role }, { role }] : [] }));
    await expect(
      readRoleBindingPreview({ query } as unknown as PoolClient, participantId, roleId),
    ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  });

  it('changes the digest when role revision or immutable creator provenance changes', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ role }] })
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ role: { ...role, version: '4' } }] })
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [{ role: { ...role, bootstrapMandateId: null } }],
      });
    const client = { query } as unknown as PoolClient;
    const original = await readRoleBindingPreview(client, participantId, roleId);
    const revised = await readRoleBindingPreview(client, participantId, roleId);
    const changedOrigin = await readRoleBindingPreview(client, participantId, roleId);
    expect(new Set([original.roleDigest, revised.roleDigest, changedOrigin.roleDigest]).size).toBe(
      3,
    );
  });
});
