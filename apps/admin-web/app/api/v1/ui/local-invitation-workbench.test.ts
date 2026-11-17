import { NextRequest } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import { mutateInvitationWorkbench, readInvitationWorkbench } from './local-invitation-workbench';
import { invitationState } from '../../../../lib/invitation-workflow';
import {
  authenticated,
  localRuntimeConfig,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { digest, principalCreateAction } from './local-governance-api';

vi.mock('./local-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (value: string) => `018f0000-0000-7000-8000-${value.padStart(12, '0')}`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

it('prepares invitations through the same public origin that issues the session CSRF token', async () => {
  const session: IdentitySession = {
    sessionId: id('701'),
    principalId: id('111'),
    participantId: id('101'),
    privacyDomainId: id('201'),
    contextEpoch: '2',
    contextMode: 'PARTICIPANT',
    sessionToken: 'synthetic-session',
    role: 'operator',
    stepUpVerifiedAt: null,
  };
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue({
    cookieKey: Buffer.from('cookie'.repeat(32)),
    publicApiUrl: 'http://gateway:8080',
    identityUrl: 'http://identity:3001',
  } as LocalConfig);
  const change = {
    mutation: 'CREATE',
    invitationId: id('702'),
    displayName: 'Invited colleague',
    recipientSubject: 'provider-subject',
    intendedRoleId: id('703'),
    tokenDigest: `sha256:${'a'.repeat(64)}`,
    ttlSeconds: 3600,
  };
  const candidate = {
    change,
    expectedRevision: '0',
    issuer: 'https://provider.test',
    audience: 'workbench',
  };
  const requests: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
    const target = new URL(String(url)),
      headers = new Headers(options?.headers);
    requests.push(target.pathname);
    // Model the real owner's same-origin admission, including its CSRF origin binding.
    if (target.origin !== headers.get('origin') || target.origin !== 'http://gateway:8080')
      return Response.json({ code: 'PC-IDENTITY-1009' }, { status: 403 });
    expect(headers.get('cookie')).toBe('__Host-openpc_session=synthetic-session');
    if (target.pathname === '/api/v1/session/csrf')
      return Response.json({ csrfToken: 'c'.repeat(32) });
    expect(target.pathname).toBe('/v1/identity/invitations/prepare');
    expect(headers.get('x-csrf-token')).toBe('c'.repeat(32));
    expect(JSON.parse(String(options?.body))).toEqual(change);
    return Response.json({
      state: 'PREPARED',
      candidate,
      candidateDigest: digest(candidate),
      expectedRevision: '0',
      resourceId: change.invitationId,
      actionIntentId: principalCreateAction.id,
      catalogOperationId: 'ID-OP-INVITATION-CREATE',
    });
  });
  const response = await mutateInvitationWorkbench(
    new NextRequest('http://localhost:8080/api/v1/ui/invitation-workbench', {
      method: 'POST',
      headers: {
        'host': 'localhost:8080',
        'origin': 'http://localhost:8080',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        command: 'PREPARE',
        input: change,
        reason: 'Invite the reviewed colleague.',
        checkerPrincipalId: id('112'),
        expectedSessionId: session.sessionId,
      }),
    }),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    review: { candidate, candidateDigest: digest(candidate) },
  });
  expect(requests).toEqual(['/api/v1/session/csrf', '/v1/identity/invitations/prepare']);
});

it.each(['APPROVAL_REQUESTED', 'APPROVED', 'CONSUMED'] as const)(
  'renders the checker inbox with the public candidate lifecycle state %s',
  async (state) => {
    const session: IdentitySession = {
      sessionId: id('701'),
      principalId: id('112'),
      participantId: id('101'),
      privacyDomainId: id('201'),
      contextEpoch: '2',
      contextMode: 'PARTICIPANT',
      sessionToken: 'synthetic-checker',
      role: 'operator',
      stepUpVerifiedAt: null,
    };
    vi.mocked(authenticated).mockResolvedValue(session);
    vi.mocked(localRuntimeConfig).mockResolvedValue({
      publicApiUrl: 'http://gateway:8080',
      identityUrl: 'http://identity:3001',
    } as LocalConfig);
    const candidate = {
      change: { mutation: 'REVOKE', invitationId: id('702') },
      expectedRevision: '1',
      issuer: 'https://provider.test',
      audience: 'workbench',
    };
    const candidateDigest = digest(candidate),
      now = new Date().toISOString();
    const item = {
      approvalRequestId: `urn:openpc:resource:${id('801')}`,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      candidateDigest,
      state: state === 'APPROVAL_REQUESTED' ? 'REQUESTED' : 'APPROVED',
      makerSubjectRef: `urn:openpc:resource:${id('111')}`,
      checkerSubjectRef: `urn:openpc:resource:${session.principalId}`,
      revision: state === 'APPROVAL_REQUESTED' ? '1' : '2',
      createdAt: now,
      updatedAt: now,
    };
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
      const target = new URL(String(url));
      expect(target.origin).toBe('http://gateway:8080');
      expect(new Headers(options?.headers).get('origin')).toBe(target.origin);
      if (target.pathname === '/api/v1/approval-requests')
        return Response.json({
          items: [item],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        });
      expect(decodeURIComponent(target.pathname)).toBe(
        `/v1/identity/invitation-proposals/${candidateDigest}`,
      );
      expect(target.searchParams.get('approvalRequestId')).toBe(id('801'));
      return Response.json({
        candidate,
        candidateDigest,
        resourceId: id('702'),
        catalogOperationId: 'ID-OP-INVITATION-REVOKE',
        expectedRevision: '1',
        state,
        expiresAt: new Date(Date.now() + 300000).toISOString(),
        makerPrincipalId: id('111'),
        operationId: state === 'CONSUMED' ? id('802') : null,
        approval: { approvalRequestId: id('801'), reason: 'Revoke the reviewed invitation.' },
      });
    });
    const response = await readInvitationWorkbench(
      new NextRequest('http://localhost:8080/api/v1/ui/invitation-workbench?lane=checker'),
    );
    expect(response.status).toBe(200);
    const page = invitationState.parse(await response.json());
    expect(page.approvals).toHaveLength(1);
    expect(page.approvals[0]?.proposal.state).toBe(state);
  },
);
