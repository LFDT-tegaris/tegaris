import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { ownerJson } from './local-governance-api';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readRpcAccessWorkbench } from './local-rpc-access-workbench';
import { mutateGrantWorkbench, readGrantWorkbench } from './local-grant-workbench';
import {
  readPendingAdministrator,
  readPendingAdministratorPreparation,
} from './platform-administrator-selection';
import { pendingPlatformRecoveryFixture } from '../../../../../../services/identity-service/src/domain/platform-recovery.test-fixture';
import {
  authenticated,
  localRuntimeConfig,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
vi.mock('./platform-administrator-selection', () => ({
  readPendingAdministrator: vi.fn(),
  readPendingAdministratorPreparation: vi.fn(),
}));
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const session: IdentitySession = {
  sessionToken: 'mock-private-session',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId,
  contextMode: 'PLATFORM',
  contextEpoch: '2',
  platformBootstrapEligible: true,
  stepUpVerifiedAt: null,
};
const runtime: LocalConfig = {
  publicApiUrl: 'http://owner.invalid',
  identityUrl: 'http://identity.invalid',
  factUrl: 'http://fact.invalid',
  policyUrl: 'http://policy.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'mock-secret',
  factToken: 'mock-secret',
  policyToken: 'mock-secret',
  cookieKey: randomBytes(64),
};
function request(path: string, body?: unknown) {
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/${path}`, {
    ...(body ? { method: 'POST', body: JSON.stringify(body) } : {}),
    headers: {
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'content-type': 'application/json',
    },
  });
}
function metadata() {
  return {
    participantId,
    privacyDomainId,
    actionIntentDigest: 'sha256:' + 'a'.repeat(64),
    stepUpActionIntentDigest: 'sha256:' + 'b'.repeat(64),
  };
}
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.endsWith('/bootstrap-metadata')) return Response.json(metadata());
    if (url.includes('/approval-requests?'))
      return Response.json({
        items: [],
        nextCursor: null,
        completeness: 'COMPLETE',
        authorizedEmpty: true,
        total: '0',
        snapshotRevision: '1',
      });
    throw new Error('Unexpected owner read');
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

it('loads a Platform handoff without Participant collection, RPC catalogue or invented records', async () => {
  const response = await readRpcAccessWorkbench(
    request('rpc-access-workbench?mode=platform-handoff'),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    actor: { contextMode: 'PLATFORM', privacyDomainId },
    approvalsLoaded: false,
    items: [],
    approvals: [],
  });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(readPendingAdministrator).not.toHaveBeenCalled();
});
it.each([undefined, false])(
  'rejects caller-only Platform eligibility %s before owner reads',
  async (eligible) => {
    vi.mocked(authenticated).mockResolvedValue({ ...session, platformBootstrapEligible: eligible });
    expect(
      (await readRpcAccessWorkbench(request('rpc-access-workbench?mode=platform-handoff'))).status,
    ).toBe(404);
    expect(fetch).not.toHaveBeenCalled();
  },
);
it('rejects incomplete administrator selectors without reading a candidate', async () => {
  expect(
    (
      await readRpcAccessWorkbench(
        request(`rpc-access-workbench?mode=platform-handoff&principalId=${session.principalId}`),
      )
    ).status,
  ).toBe(400);
  expect(readPendingAdministrator).not.toHaveBeenCalled();
});
it('admits the fixed Platform assignment inbox using authoritative privacy metadata', async () => {
  const response = await readGrantWorkbench(request('grant-workbench?mode=platform-handoff'));
  expect(response?.status).toBe(200);
  expect(await response?.json()).toMatchObject({
    actor: { principalId: session.principalId, participantId, privacyDomainId },
    approvalsLoaded: false,
    approvals: [],
  });
});
it('does not admit Platform grants on the ordinary Participant surface', async () => {
  expect((await readGrantWorkbench(request('grant-workbench')))?.status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});
it('rejects foreign authoritative metadata and does not read an approval inbox', async () => {
  vi.mocked(fetch).mockResolvedValue(
    Response.json({ ...metadata(), privacyDomainId: '018f0000-0000-7000-8000-000000000202' }),
  );
  expect((await readGrantWorkbench(request('grant-workbench?mode=platform-handoff')))?.status).toBe(
    404,
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});
it('rejects delegation readback on the Platform handoff surface', async () => {
  expect(
    (await readGrantWorkbench(request('grant-workbench?mode=platform-handoff&kind=delegation')))
      ?.status,
  ).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(1);
});
it('rejects arbitrary Platform assignment previews before subject or grant reads', async () => {
  const response = await mutateGrantWorkbench(
    request('grant-workbench?mode=platform-handoff', {
      command: 'PREVIEW_ASSIGN',
      principalId: session.principalId,
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000000721',
      actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
      capabilityIds: [],
      resourceIds: [session.principalId],
      riskClasses: ['LOW'],
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 3600000).toISOString(),
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
      reason: 'An arbitrary assignment must not become a handoff.',
    }),
  );
  expect(response.status).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([null, new Date(Date.now() - 300001).toISOString()])(
  'requests only a derived handoff READ proof before stale readiness: %s',
  async (verifiedAt) => {
    const { intent } = pendingPlatformRecoveryFixture();
    const prepared = {
      plan: intent.preparation,
      administrator: intent.preparation.administrators[0]!,
      checkerPrincipalId: intent.preparation.administrators[1]!.principalId,
    };
    vi.mocked(authenticated).mockResolvedValue({ ...session, stepUpVerifiedAt: verifiedAt });
    vi.mocked(readPendingAdministratorPreparation).mockResolvedValue(prepared);
    const approvalId = '018f0000-0000-7000-8000-000000000909';
    const response = await readRpcAccessWorkbench(
      request(
        `rpc-access-workbench?mode=platform-handoff&preparationApprovalId=${approvalId}&principalId=${prepared.administrator.principalId}`,
      ),
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      actor: { principalId: session.principalId },
      requiresStepUp: {
        actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        resourceId: prepared.plan.replacementId,
        actionIntentDigest:
          'sha256:73a4a8e0cc469d63163715b94ce3882d4a66e86e3d7799cb7089dd3c5aff8ad0',
      },
    });
    expect(body.handoff).toBeUndefined();
    expect(body.approvals).toBeUndefined();
    expect(readPendingAdministratorPreparation).toHaveBeenCalledWith(
      runtime,
      expect.objectContaining({ principalId: session.principalId, privacyDomainId }),
      expect.any(NextRequest),
      approvalId,
      prepared.administrator.principalId,
    );
    expect(readPendingAdministrator).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);
it('does not offer a read proof for unavailable preparation provenance', async () => {
  vi.mocked(readPendingAdministratorPreparation).mockResolvedValue(
    new Response(null, { status: 404 }) as never,
  );
  const response = await readRpcAccessWorkbench(
    request(
      `rpc-access-workbench?mode=platform-handoff&preparationApprovalId=018f0000-0000-7000-8000-000000000909&principalId=${session.principalId}`,
    ),
  );
  expect(response.status).toBe(404);
  expect(readPendingAdministrator).not.toHaveBeenCalled();
});

it.each(['transport', 'response', 'schema'] as const)(
  'records only redacted owning handoff %s diagnostics',
  async (reason) => {
    const log = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const privateBody = 'private-session-token-and-secret-value';
    const response =
      reason === 'transport'
        ? undefined
        : new Response(JSON.stringify({ privateBody }), {
            status: reason === 'response' ? 503 : 200,
            headers: { 'content-type': 'application/json' },
          });
    const result = await ownerJson(
      response,
      z.strictObject({ supported: z.literal(true) }),
      request('rpc-access'),
      'platform-handoff-readiness',
    );
    expect(result).toBeInstanceOf(Response);
    expect(log).toHaveBeenCalledOnce();
    expect(JSON.parse(log.mock.calls[0]![0] as string)).toEqual({
      event: 'openpc.platform-administrator.owner-read-failed',
      stage: 'platform-handoff-readiness',
      reason,
      status: response?.status ?? null,
    });
    expect(JSON.stringify(log.mock.calls)).not.toContain(privateBody);
  },
);

it.each(
  [
    'valid',
    'participant',
    'role',
    'reference',
    'revision',
    'digest',
    'actions',
    'envelope',
  ].flatMap((variant) => [
    { variant, administratorIndex: 0 },
    { variant, administratorIndex: 1 },
  ]),
)(
  'binds administrator $administratorIndex assignment input to its authorized role preview: $variant',
  async ({ variant, administratorIndex }) => {
    const { intent } = pendingPlatformRecoveryFixture();
    const original = intent.preparation.administrators[administratorIndex]!;
    const usable = {
      ...original.usable,
      validFromNs: (BigInt(Date.now() - 60000) * 1000000n).toString(),
      validUntilNs: (BigInt(Date.now() + 600000) * 1000000n).toString(),
      administration: {
        ...original.usable.administration,
        participantIds: [participantId],
        privacyDomainIds: [privacyDomainId],
      },
    };
    const administrator = { ...original, usable };
    const prepared = {
      plan: intent.preparation,
      administrator,
      checkerPrincipalId: intent.preparation.administrators[1]!.principalId,
    };
    vi.mocked(readPendingAdministrator).mockResolvedValue(prepared);
    const otherId = '018f0000-0000-7000-8000-000000000999';
    const binding = {
      participantId: variant === 'participant' ? otherId : participantId,
      roleId: variant === 'role' ? otherId : administrator.roleId,
      roleRef: `urn:openpc:role:${variant === 'reference' ? otherId : administrator.roleId}`,
      revision: variant === 'revision' ? '999' : administrator.expectedRoleRevision,
      roleDigest: variant === 'digest' ? `sha256:${'f'.repeat(64)}` : administrator.roleDigest,
      actionIntentIds:
        variant === 'actions' ? ['ACT-UNRELATED_ACTION-V1'] : usable.administration.actionIntentIds,
    };
    vi.mocked(fetch).mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/bootstrap-metadata')) return Response.json(metadata());
      if (url.endsWith(`/identity/principals/${administrator.principalId}`))
        return Response.json({ code: 'PC-AUTH-0005' }, { status: 404 });
      if (url.endsWith(`/envelopes/${administrator.envelopeId}`))
        return Response.json({
          effect: {
            id: administrator.envelopeId,
            participantId,
            state: 'ACTIVE',
            authorityEpoch: '1',
            revision: '4',
            semanticDigest: `sha256:${'a'.repeat(64)}`,
            platformScopeReplacementId:
              variant === 'envelope' ? otherId : prepared.plan.replacementId,
            privacyDomainIds: [privacyDomainId],
            actionIntentIds: usable.administration.actionIntentIds,
            capabilityIds: [],
            resourceIds: usable.administration.resourceIds,
            riskClasses: usable.administration.riskClasses,
            validFrom: new Date(Number(BigInt(usable.validFromNs) / 1000000n)).toISOString(),
            validUntil: new Date(Number(BigInt(usable.validUntilNs) / 1000000n)).toISOString(),
            makerCheckerRequired: true,
            stepUpRequired: true,
            onwardDelegationDepth: 0,
          },
          operationId: null,
        });
      if (url.endsWith(`/roles/${administrator.roleId}/binding-preview`))
        return Response.json(binding);
      throw new Error(
        'Unexpected owner read; ordinary role read must not serve a Platform handoff.',
      );
    });
    const response = await mutateGrantWorkbench(
      request('grant-workbench?mode=platform-handoff', {
        command: 'PREVIEW_PENDING_ASSIGNMENT',
        approvalRequestId: '018f0000-0000-7000-8000-000000000909',
        principalId: administrator.principalId,
        reason: 'Complete the signed two-administrator handoff.',
      }),
    );
    expect(response.status).toBe(variant === 'valid' ? 201 : variant === 'actions' ? 400 : 412);
    const body = await response.json();
    if (variant === 'valid')
      expect(body.review.proposedGrant).toMatchObject({
        id: administrator.assignmentId,
        principalId: administrator.principalId,
        authorityEnvelopeId: administrator.envelopeId,
        roleId: `urn:openpc:role:${administrator.roleId}`,
      });
    else expect(body.reviewToken).toBeUndefined();
    expect(
      vi.mocked(fetch).mock.calls.every(([, init]) => !init?.method || init.method === 'GET'),
    ).toBe(true);
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(([input]) => String(input).includes('/identity/principals/')),
    ).toBe(false);
  },
);
