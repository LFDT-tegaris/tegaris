import { NextRequest } from 'next/server';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { mutateDirectoryWorkbench } from './local-directory-workbench';
import {
  authenticated,
  localRuntimeConfig,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { digest, participantAction } from './local-governance-api';
vi.mock('./local-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (value: string) => `018f0000-0000-7000-8000-${value.padStart(12, '0')}`;
const actor = {
  sessionId: id('701'),
  principalId: id('111'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  contextEpoch: '2',
};
const session: IdentitySession = {
  ...actor,
  sessionToken: 'synthetic-session-token',
  role: 'operator',
  contextMode: 'PARTICIPANT',
  stepUpVerifiedAt: null,
};
const config = {
  cookieKey: Buffer.from('cookie'.repeat(32)),
  publicApiUrl: 'http://owner.test',
} as LocalConfig;
const now = new Date().toISOString(),
  expiresAt = new Date(Date.now() + 300000).toISOString();
const candidate = {
  connectorId: id('192'),
  mode: 'RECONCILE',
  expectedRevision: '4',
  profileDigest: `sha256:${'c'.repeat(64)}`,
  observedAt: now,
  reviewClass: 'MASS_CHANGE',
  managedMembers: 1,
  changedMembers: 1,
  members: [
    {
      externalId: 'provider-A',
      principalId: id('142'),
      expectedPrincipalRevision: '1',
      displayName: 'Directory colleague',
      source: {
        resourceType: 'User',
        id: 'provider-A',
        version: 'W/"2"',
        lastModified: now,
        userName: 'directory-user',
        displayName: 'Directory colleague',
        active: false,
      },
    },
  ],
};
const candidateDigest = digest(candidate),
  reason = 'Offboard the reviewed disabled directory account.';
const value = {
  candidate,
  resourceId: id('192'),
  expectedRevision: '4',
  candidateDigest,
  checkerPrincipalId: id('112'),
  reason,
  expiresAt,
  stepUp: {
    actionIntentId: participantAction.id,
    actionIntentDigest: participantAction.digest,
    resourceId: id('192'),
    resourceDigest: candidateDigest,
  },
  actor,
  origin: 'http://localhost:8080',
  idempotencyKey: 'directory-test-unique-idempotency',
};
const reviewToken = sealBffPayload(value, config.cookieKey, 'directory-review');
const approval = {
  approvalRequestId: `urn:openpc:resource:${id('801')}`,
  actionIntentId: participantAction.id,
  candidateDigest,
  state: 'APPROVED',
  makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
  checkerSubjectRef: `urn:openpc:resource:${id('112')}`,
  revision: '2',
  createdAt: now,
  updatedAt: now,
};
const proposal = {
  candidateDigest,
  resourceId: id('192'),
  makerPrincipalId: actor.principalId,
  catalogOperationId: 'ID-OP-DIRECTORY-MASS-RECONCILE',
  expectedRevision: '4',
  state: 'PROPOSED',
  operationId: null,
  expiresAt,
  candidate,
  approval: { approvalRequestId: id('801'), reason },
};
const record = {
  connectorId: id('192'),
  participantId: actor.participantId,
  profileId: id('141'),
  profileDigest: candidate.profileDigest,
  displayName: 'Corporate directory',
  massChangeThreshold: 5,
  externalGroupFreshnessSeconds: 900,
  state: 'ACTIVE',
  revision: '5',
  operationId: id('850'),
  createdAt: now,
  updatedAt: now,
};
function request(token = reviewToken) {
  return new NextRequest('http://localhost:8080/api/v1/ui/directory-workbench', {
    method: 'POST',
    headers: {
      'host': 'localhost:8080',
      'origin': 'http://localhost:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ command: 'COMMIT', reviewToken: token, approvalRequestId: id('801') }),
  });
}
function ownerResponses(afterStatus: number, mutation: 'success' | 'lost' | 'denied' = 'success') {
  let proposals = 0;
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
    const path = String(url);
    if (path.includes('/api/v1/approval-requests/')) return Response.json(approval);
    if (path.includes('/directory-proposals/'))
      return ++proposals === 1
        ? Response.json(proposal)
        : Response.json({ code: 'upstream-concealed-or-unavailable' }, { status: afterStatus });
    if (path.endsWith('/api/v1/session/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
    if (path.endsWith('/directory-reconciliation/mutate')) {
      expect(JSON.parse(String(options?.body))).toEqual(candidate);
      if (mutation === 'lost') throw new TypeError('Simulated response loss');
      if (mutation === 'denied')
        return Response.json({ code: 'revision-conflict' }, { status: 409 });
      return Response.json({
        effect: {
          connector: record,
          members: [
            {
              externalId: 'provider-A',
              principalId: id('142'),
              state: 'OFFBOARDED',
              revision: '2',
            },
          ],
        },
      });
    }
    throw new Error(`Unexpected owner request ${path}`);
  });
}
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue(config);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});
it('retains the actual commit across a concealed authentication failure and asks for reauthentication', async () => {
  ownerResponses(404);
  const response = await mutateDirectoryWorkbench(request());
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    truthState: 'SUCCESS',
    operationId: id('850'),
    requiresReauthentication: true,
    readback: { effect: record },
  });
});
it('retains a confirmed commit during readback outage without claiming an authentication failure', async () => {
  ownerResponses(503);
  expect(await (await mutateDirectoryWorkbench(request())).json()).toMatchObject({
    truthState: 'SUCCESS',
    operationId: id('850'),
    requiresReauthentication: false,
  });
});
it('does not invent a commit when both the response and authorized reconciliation are unavailable', async () => {
  ownerResponses(404, 'lost');
  const response = await mutateDirectoryWorkbench(request());
  expect(response.status).toBe(202);
  expect(await response.json()).toEqual({ truthState: 'WRITE_AMBIGUITY' });
});
it('preserves a business conflict even when its subsequent readback is concealed', async () => {
  ownerResponses(404, 'denied');
  const response = await mutateDirectoryWorkbench(request());
  expect(response.status).toBe(409);
  expect(await response.json()).toMatchObject({ code: 'PC-RUNTIME-3007' });
});
it('rejects a sealed review after session renewal before any public write', async () => {
  vi.mocked(authenticated).mockResolvedValue({ ...session, sessionId: id('702') });
  const calls = vi.spyOn(globalThis, 'fetch');
  expect((await mutateDirectoryWorkbench(request())).status).toBe(404);
  expect(calls).not.toHaveBeenCalled();
});

it('commits a sealed group projection through Participant and retains its result after epoch invalidation', async () => {
  const groupId = id('193');
  const candidate = {
    mutation: 'REFRESH_DIRECTORY',
    groupId,
    connectorId: id('192'),
    externalGroupId: 'external-group',
    expectedRevision: '4',
    reviewClass: 'MASS_CHANGE',
    managedMembers: 1,
    changedMembers: 1,
    members: [],
    observation: {
      participantId: actor.participantId,
      connectorId: id('192'),
      connectorRevision: '2',
      profileDigest: `sha256:${'c'.repeat(64)}`,
      observedAt: now,
      freshUntil: new Date(Date.parse(now) + 900000).toISOString(),
      externalGroupFreshnessSeconds: 900,
      massChangeThreshold: 5,
      source: {
        resourceType: 'Group',
        id: 'external-group',
        version: 'W/"2"',
        lastModified: now,
        displayName: 'External group',
        members: [],
      },
    },
  };
  const candidateDigest = digest(candidate);
  const groupValue = {
    ...value,
    candidate,
    resourceId: groupId,
    candidateDigest,
    stepUp: { ...value.stepUp, resourceId: groupId, resourceDigest: candidateDigest },
  };
  const record = {
    group: {
      effect: {
        groupId,
        participantId: actor.participantId,
        groupName: 'Local group',
        state: 'ACTIVE',
        revision: '5',
        createdAt: now,
        updatedAt: now,
        operationId: id('851'),
      },
      members: [],
      nextCursor: null,
    },
    mapping: {
      connectorId: id('192'),
      externalGroupId: 'external-group',
      profileDigest: candidate.observation.profileDigest,
      providerVersion: 'W/"2"',
      providerModifiedAt: now,
      observedAt: now,
      freshUntil: candidate.observation.freshUntil,
      fresh: true,
      revision: '3',
      operationId: id('851'),
    },
  };
  let proposals = 0;
  const owner = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
    const path = String(url);
    if (path.includes('/api/v1/approval-requests/'))
      return Response.json({ ...approval, candidateDigest });
    if (path.includes('/group-proposals/'))
      return ++proposals === 1
        ? Response.json({
            ...proposal,
            candidate,
            resourceId: groupId,
            candidateDigest,
            catalogOperationId: 'ID-OP-GROUP-DIRECTORY-MASS-REFRESH',
          })
        : Response.json({ code: 'concealed' }, { status: 404 });
    if (path.endsWith('/api/v1/session/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
    if (path.endsWith(`/v1/participants/${actor.participantId}/directory-groups/mutate`)) {
      expect(JSON.parse(String(options?.body))).toEqual(candidate);
      expect(new Headers(options?.headers).get('authorization')).toBe(
        `Bearer ${session.sessionToken}`,
      );
      return Response.json({ ...record, revokedAssignments: 1 });
    }
    throw new Error(`Unexpected owner request ${path}`);
  });
  const response = await mutateDirectoryWorkbench(
    request(
      sealBffPayload(
        { ...groupValue, candidate: undefined, group: true },
        config.cookieKey,
        'directory-review',
      ),
    ),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    truthState: 'SUCCESS',
    operationId: id('851'),
    readback: record,
    requiresReauthentication: true,
  });
  expect(
    owner.mock.calls.some(([url]) => String(url).includes('/directory-reconciliation/mutate')),
  ).toBe(false);
});
