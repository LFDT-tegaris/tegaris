import type { Pool, PoolClient } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';

import { runScopedTransaction } from '../db/scoped-transaction.js';
import type { IdentityKernel } from './identity-kernel.js';
import { IdentityKernelError } from './identity-kernel.js';
import { discoveryCertificateRecoveryPolicyScope } from './discovery-certificate-recovery-policy.js';
import { platformBootstrapPolicyScope } from './platform-bootstrap-policy.js';
import {
  authorizeLocalPolicyAction,
  type PolicyAuthorizationContext,
} from './policy-authorization.js';

vi.mock('../db/scoped-transaction.js', () => ({ runScopedTransaction: vi.fn() }));
vi.mock('./discovery-certificate-recovery-policy.js', () => ({
  discoveryCertificateRecoveryPolicyScope: vi.fn(),
}));
vi.mock('./platform-bootstrap-policy.js', () => ({ platformBootstrapPolicyScope: vi.fn() }));
vi.mock('./recovery-principal.js', () => ({ assertRecoveryPrincipalAction: vi.fn() }));

afterEach(() => vi.resetAllMocks());

const participantId = '018f0000-0000-7000-8000-000000000101';
const sessionId = '018f0000-0000-7000-8000-000000000701';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const context = {
  sessionId,
  sessionEpoch: '1',
  sessionIssuedAt: new Date('2026-09-29T00:00:00.000Z'),
  sessionIdleExpiresAt: new Date('2026-09-29T00:30:00.000Z'),
  sessionAbsoluteExpiresAt: new Date('2026-09-29T12:00:00.000Z'),
  participantId,
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantEpoch: '1',
  principalEpoch: '1',
  assignmentId: '018f0000-0000-7000-8000-000000000801',
  assignmentRowVersion: '1',
  authorityEnvelopeId: '018f0000-0000-7000-8000-000000000901',
  authorityEpoch: '1',
  delegationEpoch: '0',
} satisfies PolicyAuthorizationContext;
const kernel = {
  sessionSnapshot: vi.fn().mockResolvedValue({
    ...context,
    contextMode: 'PLATFORM',
  }),
} as unknown as IdentityKernel;

it('admits the exact authenticated session as the only platform logout target', async () => {
  vi.mocked(runScopedTransaction).mockResolvedValue(context);
  const input = {
    sessionToken: `${participantId}.${sessionId}`,
    privacyDomainId,
    actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REVOKE',
    resourceId: sessionId,
    stepUpRequired: false,
    allowPlatformContextSelection: true,
  };

  await expect(authorizeLocalPolicyAction({} as Pool, kernel, input)).resolves.toEqual(context);
  expect(runScopedTransaction).toHaveBeenCalledOnce();

  vi.mocked(runScopedTransaction).mockClear();
  await expect(
    authorizeLocalPolicyAction({} as Pool, kernel, {
      ...input,
      resourceId: '018f0000-0000-7000-8000-000000000702',
    }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' } satisfies Partial<IdentityKernelError>);
  expect(runScopedTransaction).not.toHaveBeenCalled();

  await expect(
    authorizeLocalPolicyAction({} as Pool, kernel, {
      ...input,
      actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' } satisfies Partial<IdentityKernelError>);
  expect(runScopedTransaction).not.toHaveBeenCalled();
});

it('admits the exact authenticated session as the only platform refresh target', async () => {
  const refreshKernel = {
    sessionSnapshot: vi.fn().mockResolvedValue({ ...context, contextMode: 'PLATFORM' }),
  } as unknown as IdentityKernel;
  vi.mocked(runScopedTransaction).mockResolvedValue(context);
  const input = {
    sessionToken: `${participantId}.${sessionId}`,
    privacyDomainId,
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REFRESH',
    resourceId: sessionId,
    stepUpRequired: false,
    allowPlatformContextSelection: true,
  };

  await expect(authorizeLocalPolicyAction({} as Pool, refreshKernel, input)).resolves.toEqual(
    context,
  );
  expect(runScopedTransaction).toHaveBeenCalledOnce();

  vi.mocked(runScopedTransaction).mockClear();
  await expect(
    authorizeLocalPolicyAction({} as Pool, refreshKernel, {
      ...input,
      resourceId: '018f0000-0000-7000-8000-000000000702',
    }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' } satisfies Partial<IdentityKernelError>);
  expect(runScopedTransaction).not.toHaveBeenCalled();

  await expect(
    authorizeLocalPolicyAction({} as Pool, refreshKernel, {
      ...input,
      actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' } satisfies Partial<IdentityKernelError>);
  expect(runScopedTransaction).not.toHaveBeenCalled();
  await expect(
    authorizeLocalPolicyAction({} as Pool, refreshKernel, { ...input, resourceId: participantId }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });
  expect(runScopedTransaction).not.toHaveBeenCalled();

  await expect(
    authorizeLocalPolicyAction({} as Pool, refreshKernel, {
      ...input,
      catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
    }),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });
  expect(runScopedTransaction).not.toHaveBeenCalled();
  await expect(
    authorizeLocalPolicyAction({} as Pool, refreshKernel, {
      ...input,
      catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
      resourceId: participantId,
    }),
  ).resolves.toEqual(context);
  expect(runScopedTransaction).toHaveBeenCalledOnce();
});

it.each(['same envelope', 'different envelope', 'missing ordinary grant', 'denied purpose'])(
  'requires %s after purpose context admission',
  async (reason) => {
    const recoveredKernel = {
      sessionSnapshot: vi.fn().mockResolvedValue({
        ...context,
        authorityEpoch: '1',
        contextMode: 'PLATFORM',
      }),
    } as unknown as IdentityKernel;
    vi.mocked(discoveryCertificateRecoveryPolicyScope).mockResolvedValue(
      reason === 'denied purpose' ? false : { authorityEnvelopeId: context.authorityEnvelopeId },
    );
    const query = vi.fn().mockResolvedValue({
      rowCount: reason === 'missing ordinary grant' ? 0 : 1,
      rows: [
        {
          ...context,
          authorityEnvelopeId:
            reason === 'different envelope'
              ? '018f0000-0000-7000-8000-000000000902'
              : context.authorityEnvelopeId,
        },
      ],
    });
    vi.mocked(runScopedTransaction).mockImplementation(async (_pool, _scope, _id, operation) =>
      operation({ query } as unknown as PoolClient, 'operation-id'),
    );
    const input = {
      sessionToken: `${participantId}.${sessionId}`,
      privacyDomainId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
      resourceId: '018f0000-0000-7000-8000-000000000192',
      stepUpRequired: false,
    };
    if (reason === 'same envelope') {
      await expect(authorizeLocalPolicyAction({} as Pool, recoveredKernel, input)).resolves.toEqual(
        context,
      );
      expect(query.mock.calls[0]![1][8]).toBe(true);
    } else {
      await expect(
        authorizeLocalPolicyAction({} as Pool, recoveredKernel, input),
      ).rejects.toMatchObject({
        code: 'PC-IDENTITY-1002',
      });
    }
    expect(platformBootstrapPolicyScope).not.toHaveBeenCalled();
    if (reason === 'denied purpose') expect(query).not.toHaveBeenCalled();
  },
);
