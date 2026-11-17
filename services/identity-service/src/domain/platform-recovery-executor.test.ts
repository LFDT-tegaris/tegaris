import { expect, it, vi } from 'vitest';
import { assertRecoveryPrincipalAction } from './recovery-principal.js';
const input = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  principalId: '018f0000-0000-7000-8000-000000000111',
  resourceId: '018f0000-0000-7000-8000-000000000401',
};
it.each([
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
])(
  'permits executor identity custody without claiming business authority: %s',
  async (actionIntentId) => {
    const query = vi.fn().mockResolvedValue({ rows: [{ registered: true }], rowCount: 1 });
    await expect(
      assertRecoveryPrincipalAction({ query } as never, { ...input, actionIntentId }),
    ).resolves.toBeUndefined();
    expect(query).toHaveBeenCalledOnce();
  },
);
it.each([
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
])('an enrolled executor cannot use an ordinary grant for %s', async (actionIntentId) => {
  const query = vi.fn().mockResolvedValue({ rows: [{ registered: true }], rowCount: 1 });
  await expect(
    assertRecoveryPrincipalAction({ query } as never, { ...input, actionIntentId }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
  expect(query).toHaveBeenCalledOnce();
});
it('leaves ordinary identities under the existing participant recovery restriction', async () => {
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rows: [{ registered: false }], rowCount: 1 })
    .mockResolvedValueOnce({ rows: [], rowCount: 0 });
  await expect(
    assertRecoveryPrincipalAction({ query } as never, {
      ...input,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    }),
  ).resolves.toBeUndefined();
  expect(query).toHaveBeenCalledTimes(2);
});
