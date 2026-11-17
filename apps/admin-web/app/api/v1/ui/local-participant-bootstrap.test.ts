// Caller-owner regressions use mocked public HTTP responses; native READ authority remains unproved.
import { createHash } from 'node:crypto';
import { NextRequest } from 'next/server';
import { afterEach, expect, it, vi } from 'vitest';
import { participantBootstrapWorkbench } from './local-participant-bootstrap';
import {
  authenticated,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
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
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});
it('keeps creation custody actor-bound and refuses a substituted committed receipt before releasing the invitation', async () => {
  const session: IdentitySession = {
    sessionId: id(701),
    principalId: id(111),
    participantId: id(101),
    contextEpoch: '1',
    contextMode: 'PLATFORM',
    platformBootstrapEligible: true,
    sessionToken: 'test-session',
    role: 'viewer',
    stepUpVerifiedAt: null,
  };
  const runtime = {
    cookieKey: Buffer.from('cookie'.repeat(32)),
    publicApiUrl: 'http://gateway:8080',
    identityUrl: 'http://identity:3001',
  } as LocalConfig;
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  const meta = {
    participantId: id(101),
    privacyDomainId: id(201),
    actionIntentDigest: `sha256:${'a'.repeat(64)}`,
    stepUpActionIntentDigest: `sha256:${'b'.repeat(64)}`,
  };
  let committed: unknown;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
    const path = new URL(String(url)).pathname;
    if (path === '/v1/participants/bootstrap-metadata') return Response.json(meta);
    if (path.startsWith('/v1/participants/bootstrap-proposals/')) return Response.json(committed);
    const headers = new Headers(options?.headers);
    expect(headers.get('origin')).toBe('http://gateway:8080');
    expect(headers.get('cookie')).toBe('__Host-openpc_session=test-session');
    if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(32) });
    if (path === '/api/v1/approval-requests') {
      expect(headers.get('x-openpc-action-intent-digest')).toBeTruthy();
      return Response.json({
        operationId: id(905),
        actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
        intentDigest: digest('approval'),
        idempotencyKey: 'approval-test-request',
        resourceRef: `urn:openpc:resource:${id(906)}`,
        revision: '1',
        state: 'ACCEPTED',
        truthState: 'SUCCESS',
        createdAt: '2026-09-16T12:00:00.000Z',
        updatedAt: '2026-09-16T12:00:00.000Z',
      });
    }
    expect(path).toBe('/v1/participants/prepare');
    const candidate = JSON.parse(String(options?.body));
    return Response.json({
      candidate,
      candidateDigest: digest(candidate),
      expectedRevision: '0',
      actionIntentDigest: meta.actionIntentDigest,
    });
  });
  const run = (body: unknown, origin = 'http://localhost:8080') =>
    participantBootstrapWorkbench(
      new NextRequest('http://localhost:8080/api/v1/ui/participant-bootstrap', {
        method: 'POST',
        headers: { 'host': 'localhost:8080', origin, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );
  const prepared = await run({
    command: 'PREPARE',
    displayName: 'New Participant',
    administratorName: 'First administrator',
    recipientIssuer: 'https://provider.example',
    recipientSubject: 'recipient',
    recipientAudience: 'workbench',
    ttlMinutes: 1440,
    checkerPrincipalId: id(112),
    reason: 'Independently reviewed first administration.',
    actionIntentIds: Array.from(
      { length: 64 },
      (_, index) => `ACT-PARTICIPANTS_READ_RESOURCE_${index}-V1`,
    ),
  });
  expect(prepared.status).toBe(202);
  const value = await prepared.json();
  const opened = openBffPayload(
    value.reviewToken,
    runtime.cookieKey,
    'participant-bootstrap-review',
  ) as { secret: string; sourcePrivacyDomainId: string };
  expect(opened.sourcePrivacyDomainId).toBe(meta.privacyDomainId);
  expect(JSON.stringify(value)).not.toContain(opened.secret);
  const submission = { command: 'SUBMIT', reviewToken: value.reviewToken };
  expect(Buffer.byteLength(JSON.stringify(submission))).toBeGreaterThan(4096);
  expect((await run(submission)).status).toBe(202);
  expect(parsePublicCommand(JSON.stringify(submission))).toBeUndefined();
  expect((await run({ command: 'SUBMIT', reviewToken: 'x'.repeat(70000) })).status).toBe(400);
  vi.mocked(authenticated).mockResolvedValue({ ...session, principalId: id(112) });
  const before = fetcher.mock.calls.length;
  expect(
    (await run({ command: 'COMMIT', reviewToken: value.reviewToken, approvalRequestId: id(900) }))
      .status,
  ).toBeGreaterThanOrEqual(400);
  expect(fetcher.mock.calls.length).toBe(before); // Reject the sealed actor before any owner call.
  vi.mocked(authenticated).mockResolvedValue(session);
  const first = value.candidate.firstAdministrator,
    operationId = id(901);
  const receipt = {
    operationId,
    result: {
      participantId: value.candidate.participantId,
      displayName: value.candidate.displayName,
      state: 'PROVISIONING',
      authorityEpoch: '0',
      rowVersion: '1',
      bootstrap: {
        mandateId: first.mandateId,
        invitationId: first.invitationId,
        privacyDomainId: first.privacyDomainId,
        state: 'ACTIVE',
        expiresAt: '2026-09-16T12:00:00.000Z',
        configuration: first.configuration,
        issuanceAuthorityDigest: `sha256:${'d'.repeat(64)}`,
      },
    },
  };
  const proposal = {
    candidate: value.candidate,
    candidateDigest: value.candidateDigest,
    state: 'CONSUMED',
    expiresAt: '2026-09-16T12:00:00.000Z',
    operationId,
    result: receipt,
  };
  committed = {
    ...proposal,
    result: { ...receipt, result: { ...receipt.result, participantId: id(999) } },
  };
  const rejected = await run({
    command: 'COMMIT',
    reviewToken: value.reviewToken,
    approvalRequestId: id(900),
  });
  expect(rejected.status).toBeGreaterThanOrEqual(400);
  expect(await rejected.text()).not.toContain(opened.secret);
  committed = proposal;
  const replay = await run({
    command: 'COMMIT',
    reviewToken: value.reviewToken,
    approvalRequestId: id(900),
  });
  expect(replay.status).toBe(200);
  const accepted = await replay.json();
  expect(accepted.operationId).toBe(operationId);
  expect(new URLSearchParams(new URL(accepted.invitationLink).hash.slice(1)).get('token')).toBe(
    opened.secret,
  );
  expect(
    fetcher.mock.calls.every(([url]) => new URL(String(url)).pathname !== '/v1/participants'),
  ).toBe(true);
  const count = fetcher.mock.calls.length;
  expect(
    (await run({ command: 'SESSION' }, 'http://foreign.example')).status,
  ).toBeGreaterThanOrEqual(400);
  expect(fetcher.mock.calls.length).toBe(count);
});

it.each(['ROTATE', 'REVOKE'] as const)(
  'binds %s to the original custody and validates its replay before releasing a link',
  async (mutation) => {
    const session = {
      sessionId: id(701),
      principalId: id(111),
      participantId: id(101),
      contextEpoch: '1',
      contextMode: 'PLATFORM',
      platformBootstrapEligible: true,
      sessionToken: 'test-session',
      role: 'viewer',
      stepUpVerifiedAt: null,
    } as IdentitySession;
    const runtime = {
      cookieKey: Buffer.from('cookie'.repeat(32)),
      publicApiUrl: 'http://gateway:8080',
      identityUrl: 'http://identity:3001',
    } as LocalConfig;
    vi.mocked(authenticated).mockResolvedValue(session);
    vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
    const custody = {
      participantId: id(501),
      privacyDomainId: id(502),
      mandateId: id(503),
      invitationId: id(504),
      makerPrincipalId: id(111),
      checkerPrincipalId: id(112),
      custodyGeneration: '1',
      tokenVersion: '1',
      revision: '1',
      state: 'CLAIM_PENDING',
      expiresAt: '2026-09-16T12:00:00.000Z',
      operationId: id(505),
    };
    let current = custody,
      committed: unknown;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
      const path = new URL(String(url)).pathname;
      if (path.endsWith('/bootstrap-metadata'))
        return Response.json({
          participantId: id(101),
          privacyDomainId: id(201),
          actionIntentDigest: digest('create'),
          stepUpActionIntentDigest: digest('step'),
        });
      if (path.endsWith('/first-administrator')) return Response.json(current);
      if (path.includes('/bootstrap-proposals/')) return Response.json(committed);
      if (path.endsWith('/session/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
      expect(path).toBe(`/v1/participants/${custody.participantId}/first-administrator/prepare`);
      const candidate = JSON.parse(String(options?.body));
      return Response.json({
        candidate,
        candidateDigest: digest(candidate),
        expectedRevision: '1',
        actionIntentDigest: participantAction.digest,
      });
    });
    const run = (body: unknown) =>
      participantBootstrapWorkbench(
        new NextRequest('http://localhost:8080/api/v1/ui/participant-bootstrap', {
          method: 'POST',
          headers: {
            'host': 'localhost:8080',
            'origin': 'http://localhost:8080',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        }),
      );
    const input = {
      command: 'PREPARE_CHANGE',
      participantId: custody.participantId,
      mutation,
      reason: 'Preserve the exact original recipient and deadline.',
    };
    current = { ...custody, state: 'EXPIRED' };
    expect((await run(input)).status).toBeGreaterThanOrEqual(400);
    current = { ...custody, makerPrincipalId: id(999) };
    expect((await run(input)).status).toBeGreaterThanOrEqual(400);
    current = custody;
    const prepared = await run(input);
    expect(prepared.status).toBe(202);
    const value = await prepared.json();
    const opened = openBffPayload(
      value.reviewToken,
      runtime.cookieKey,
      'participant-bootstrap-review',
    ) as { secret: string };
    expect(JSON.stringify(value)).not.toContain(opened.secret);
    const operationId = id(506),
      result = {
        ...custody,
        revision: '2',
        state: mutation === 'ROTATE' ? 'ACTIVE' : 'CANCELLED',
        custodyGeneration: mutation === 'ROTATE' ? '2' : '1',
        tokenVersion: mutation === 'ROTATE' ? '2' : '1',
        operationId,
      };
    const proposal = {
      candidate: value.candidate,
      candidateDigest: value.candidateDigest,
      state: 'CONSUMED',
      expiresAt: custody.expiresAt,
      operationId,
      result: { operationId, result },
    };
    const commit = {
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: id(900),
    };
    committed = {
      ...proposal,
      result: { operationId, result: { ...result, expiresAt: '2026-09-17T12:00:00.000Z' } },
    };
    const rejected = await run(commit);
    expect(rejected.status).toBeGreaterThanOrEqual(400);
    expect(await rejected.text()).not.toContain(opened.secret);
    committed = proposal;
    const response = await run(commit);
    expect(response.status).toBe(200);
    const saved = await response.json();
    expect(saved.operationId).toBe(operationId);
    if (mutation === 'ROTATE') {
      const fragment = new URLSearchParams(new URL(saved.invitationLink).hash.slice(1));
      expect(fragment.get('tokenVersion')).toBe('2');
      expect(fragment.get('token')).toBe(opened.secret);
    } else expect(saved.invitationLink).toBeUndefined();
  },
);

function originalFixture(mutation?: 'ROTATE' | 'REVOKE') {
  const session: IdentitySession = {
    sessionId: id(701),
    principalId: id(111),
    participantId: id(101),
    contextEpoch: '1',
    contextMode: 'PLATFORM',
    platformBootstrapEligible: false,
    sessionToken: 'original-current-session',
    role: 'viewer',
    stepUpVerifiedAt: null,
  };
  const runtime = {
    cookieKey: Buffer.from('cookie'.repeat(32)),
    publicApiUrl: 'http://gateway:8080',
    identityUrl: 'http://identity:3001',
  } as LocalConfig;
  const sourcePrivacyDomainId = id(201),
    secret = Buffer.alloc(32, 7).toString('base64url'),
    operationId = id(901);
  const custody = {
    participantId: id(501),
    privacyDomainId: id(502),
    mandateId: id(503),
    invitationId: id(504),
    makerPrincipalId: session.principalId,
    checkerPrincipalId: id(112),
    custodyGeneration: '1',
    tokenVersion: '1',
    revision: '1',
    state: 'CLAIM_PENDING',
    expiresAt: '2026-09-16T12:00:00.000Z',
    operationId: id(505),
  };
  const tokenDigest = `sha256:${createHash('sha256').update(secret).digest('hex')}`;
  const candidate = mutation
    ? {
        participantId: custody.participantId,
        mandateId: custody.mandateId,
        invitationId: custody.invitationId,
        custodyGeneration: custody.custodyGeneration,
        tokenVersion: custody.tokenVersion,
        expectedRevision: custody.revision,
        idempotencyKey: 'original-custody-change',
        change: mutation === 'ROTATE' ? { mutation, tokenDigest } : { mutation },
      }
    : {
        participantId: custody.participantId,
        displayName: 'Original Participant',
        idempotencyKey: 'original-participant-bootstrap',
        firstAdministrator: {
          invitationId: custody.invitationId,
          mandateId: custody.mandateId,
          privacyDomainId: custody.privacyDomainId,
          roleId: id(601),
          authorityEnvelopeId: id(602),
          assignmentId: id(603),
          displayName: 'Original administrator',
          recipientIssuer: 'https://provider.example',
          recipientSubject: 'original-recipient',
          recipientAudience: 'workbench',
          tokenDigest,
          actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
          configuration: { 'participant.first_admin_invite_ttl': 86400000 },
        },
      };
  const review = {
    candidate,
    ...(mutation ? { custody } : {}),
    candidateDigest: digest(candidate),
    actor: {
      participantId: session.participantId,
      principalId: session.principalId,
      sessionId: session.sessionId,
    },
    sourcePrivacyDomainId,
    origin: 'http://localhost:8080',
    checkerPrincipalId: id(112),
    reason: 'Preserve the original governed invitation.',
    secret,
    actionIntentDigest: mutation ? participantAction.digest : digest('create'),
  };
  const result = mutation
    ? {
        operationId,
        result: {
          ...custody,
          operationId,
          revision: '2',
          state: mutation === 'ROTATE' ? 'ACTIVE' : 'CANCELLED',
          custodyGeneration: mutation === 'ROTATE' ? '2' : '1',
          tokenVersion: mutation === 'ROTATE' ? '2' : '1',
        },
      }
    : {
        operationId,
        result: {
          participantId: candidate.participantId,
          displayName: candidate.displayName,
          state: 'PROVISIONING',
          authorityEpoch: '0',
          rowVersion: '1',
          bootstrap: {
            mandateId: custody.mandateId,
            invitationId: custody.invitationId,
            privacyDomainId: custody.privacyDomainId,
            state: 'ACTIVE',
            expiresAt: custody.expiresAt,
            configuration: { 'participant.first_admin_invite_ttl': 86400000 },
            issuanceAuthorityDigest: digest('original-issuance'),
          },
        },
      };
  const consumed = {
    candidate,
    candidateDigest: review.candidateDigest,
    state: 'CONSUMED',
    expiresAt: custody.expiresAt,
    operationId,
    result,
  };
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  const seal = (value: unknown = review) =>
    sealBffPayload(value, runtime.cookieKey, 'participant-bootstrap-review');
  const run = (command: 'READ_ORIGINAL' | 'COMMIT', reviewToken = seal(), origin = review.origin) =>
    participantBootstrapWorkbench(
      new NextRequest('http://localhost:8080/api/v1/ui/participant-bootstrap', {
        method: 'POST',
        headers: { 'host': 'localhost:8080', origin, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command,
          reviewToken,
          ...(command === 'COMMIT' ? { approvalRequestId: id(900) } : {}),
        }),
      }),
    );
  return { session, runtime, review, consumed, operationId, seal, run };
}

it.each(
  ([undefined, 'ROTATE', 'REVOKE'] as const).flatMap((mutation) =>
    (['READ_ORIGINAL', 'COMMIT'] as const).map((command) => ({ mutation, command })),
  ),
)(
  'reads the original $mutation $command receipt without new eligibility, metadata or effects',
  async ({ mutation, command }) => {
    const fixture = originalFixture(mutation);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, options) => {
      expect(new URL(String(url)).pathname).toBe(
        `/v1/participants/bootstrap-proposals/${fixture.review.candidate.participantId}/${encodeURIComponent(fixture.review.candidateDigest)}`,
      );
      expect(options?.method ?? 'GET').toBe('GET');
      const headers = new Headers(options?.headers);
      expect(headers.get('authorization')).toBe(`Bearer ${fixture.session.sessionToken}`);
      expect(headers.get('openpc-participant-id')).toBe(
        `urn:openpc:participant:${fixture.session.participantId}`,
      );
      expect(headers.get('openpc-privacy-domain-id')).toBe(
        `urn:openpc:privacy-domain:${fixture.review.sourcePrivacyDomainId}`,
      );
      return Response.json(fixture.consumed);
    });
    const token = fixture.seal();
    const response = await fixture.run(command, token);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const saved = await response.json();
    expect(saved.operationId).toBe(fixture.operationId);
    expect(saved.participantId).toBe(fixture.review.candidate.participantId);
    if (mutation === 'REVOKE') expect(saved.invitationLink).toBeUndefined();
    else {
      const link = new URL(saved.invitationLink);
      expect(link.origin).toBe(fixture.review.origin);
      const fragment = new URLSearchParams(link.hash.slice(1));
      expect(fragment.get('token')).toBe(fixture.review.secret);
      expect(fragment.get('invitationId')).toBe(id(504));
      expect(fragment.get('tokenVersion')).toBe(mutation === 'ROTATE' ? '2' : '1');
    }
    expect(await (await fixture.run(command, token)).json()).toEqual(saved);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it.each(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CANCELLED', 'EXPIRED'])(
  'returns explicit unconsumed %s without metadata, approval or mutation',
  async (state) => {
    const fixture = originalFixture();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(
        Response.json({ ...fixture.consumed, state, operationId: null, result: null }),
      );
    const response = await fixture.run('READ_ORIGINAL');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      state: 'NOT_CONSUMED',
      proposalState: state,
      participantId: fixture.review.candidate.participantId,
      candidateDigest: fixture.review.candidateDigest,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(new URL(String(fetcher.mock.calls[0]![0])).pathname).toContain('/bootstrap-proposals/');
  },
);

it.each(['READ_ORIGINAL', 'COMMIT'] as const)(
  'propagates native denied/unavailable or corrupt %s readback without a fallback write',
  async (command) => {
    const fixture = originalFixture();
    const fetcher = vi.spyOn(globalThis, 'fetch');
    for (const reply of [
      new Response('private-native-error', { status: 403 }),
      new Response('concealed', { status: 404 }),
      new Response('unavailable', { status: 503 }),
      Response.json({ ...fixture.consumed, candidateDigest: digest('foreign-intent') }),
      Response.json({ ...fixture.consumed, operationId: null }),
      Response.json({ ...fixture.consumed, result: null }),
      Response.json({
        ...fixture.consumed,
        result: { ...fixture.consumed.result, operationId: id(999) },
      }),
    ]) {
      fetcher.mockClear();
      fetcher.mockResolvedValueOnce(reply);
      const response = await fixture.run(command);
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(await response.text()).not.toContain(fixture.review.secret);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    fetcher.mockClear();
    fetcher.mockRejectedValueOnce(new Error('private-transport-error'));
    expect((await fixture.run(command)).status).toBeGreaterThanOrEqual(400);
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);

it('refuses foreign, stale or tampered sealed original identities before any owner call', async () => {
  const fixture = originalFixture();
  const fetcher = vi.spyOn(globalThis, 'fetch');
  const token = fixture.seal();
  for (const session of [
    undefined,
    { ...fixture.session, contextMode: 'PARTICIPANT' },
    { ...fixture.session, participantId: id(999) },
    { ...fixture.session, principalId: id(999) },
    { ...fixture.session, sessionId: id(999) },
  ]) {
    vi.mocked(authenticated).mockResolvedValue(session as IdentitySession | undefined);
    expect((await fixture.run('READ_ORIGINAL', token)).status).toBeGreaterThanOrEqual(400);
  }
  vi.mocked(authenticated).mockResolvedValue(fixture.session);
  for (const value of [
    { ...fixture.review, origin: 'http://foreign.example' },
    { ...fixture.review, candidateDigest: digest('substitution') },
    { ...fixture.review, sourcePrivacyDomainId: 'not-a-privacy-id' },
  ])
    expect((await fixture.run('READ_ORIGINAL', fixture.seal(value))).status).toBeGreaterThanOrEqual(
      400,
    );
  expect((await fixture.run('READ_ORIGINAL', `x${token.slice(1)}`)).status).toBeGreaterThanOrEqual(
    400,
  );
  expect(
    (await fixture.run('READ_ORIGINAL', token, 'http://foreign.example')).status,
  ).toBeGreaterThanOrEqual(400);
  expect(fetcher).not.toHaveBeenCalled();
});

it('keeps native admission for sealed privacy and resolves legacy privacy only through public metadata', async () => {
  const fixture = originalFixture();
  const { sourcePrivacyDomainId, ...legacy } = fixture.review;
  const legacyToken = fixture.seal(legacy);
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(new Response(null, { status: 403 }));
  expect((await fixture.run('READ_ORIGINAL', legacyToken)).status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(new URL(String(fetcher.mock.calls[0]![0])).pathname).toBe(
    '/v1/participants/bootstrap-metadata',
  );
  const metadata = {
    participantId: fixture.session.participantId,
    privacyDomainId: sourcePrivacyDomainId,
    actionIntentDigest: digest('create'),
    stepUpActionIntentDigest: digest('step'),
  };
  fetcher.mockClear();
  fetcher.mockResolvedValueOnce(Response.json({ ...metadata, participantId: id(999) }));
  expect((await fixture.run('READ_ORIGINAL', legacyToken)).status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1);
  fetcher.mockClear();
  fetcher.mockResolvedValueOnce(Response.json(metadata));
  fetcher.mockResolvedValueOnce(Response.json(fixture.consumed));
  expect((await fixture.run('READ_ORIGINAL', legacyToken)).status).toBe(200);
  expect(fetcher.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual([
    '/v1/participants/bootstrap-metadata',
    `/v1/participants/bootstrap-proposals/${fixture.review.candidate.participantId}/${encodeURIComponent(fixture.review.candidateDigest)}`,
  ]);
  // A correctly sealed scope still conveys no READ grant: native denial is final.
  fetcher.mockClear();
  fetcher.mockResolvedValueOnce(new Response(null, { status: 404 }));
  expect(
    (
      await fixture.run(
        'READ_ORIGINAL',
        fixture.seal({
          ...fixture.review,
          sourcePrivacyDomainId: id(999),
        }),
      )
    ).status,
  ).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('keeps all new-write gates after an unconsumed original COMMIT read', async () => {
  const fixture = originalFixture();
  const pending = { ...fixture.consumed, state: 'APPROVED', operationId: null, result: null };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(pending));
  expect((await fixture.run('COMMIT')).status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1); // Eligibility denial follows the genuine original read.
  vi.mocked(authenticated).mockResolvedValue({
    ...fixture.session,
    platformBootstrapEligible: true,
  });
  const metadata = {
    participantId: fixture.session.participantId,
    privacyDomainId: fixture.review.sourcePrivacyDomainId,
    actionIntentDigest: fixture.review.actionIntentDigest,
    stepUpActionIntentDigest: digest('step'),
  };
  const approval = {
    approvalRequestId: `urn:openpc:resource:${id(900)}`,
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    candidateDigest: fixture.review.candidateDigest,
    state: 'APPROVED',
    makerSubjectRef: `urn:openpc:resource:${fixture.session.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${fixture.review.checkerPrincipalId}`,
    revision: '2',
    createdAt: '2026-09-16T12:00:00.000Z',
    updatedAt: '2026-09-16T12:00:00.000Z',
  };
  for (const wrong of [
    { ...approval, state: 'REQUESTED' },
    { ...approval, candidateDigest: digest('different-candidate') },
    { ...approval, makerSubjectRef: `urn:openpc:resource:${id(999)}` },
    { ...approval, checkerSubjectRef: `urn:openpc:resource:${id(999)}` },
  ]) {
    fetcher.mockClear();
    fetcher.mockResolvedValueOnce(Response.json(pending));
    fetcher.mockResolvedValueOnce(Response.json(metadata));
    fetcher.mockResolvedValueOnce(Response.json(wrong));
    expect((await fixture.run('COMMIT')).status).toBeGreaterThanOrEqual(400);
    expect(fetcher).toHaveBeenCalledTimes(3);
  }
  fetcher.mockClear();
  fetcher.mockResolvedValueOnce(Response.json(pending));
  fetcher.mockResolvedValueOnce(Response.json({ ...metadata, privacyDomainId: id(999) }));
  expect((await fixture.run('COMMIT')).status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(2);
  fetcher.mockClear();
  let reads = 0;
  fetcher.mockImplementation(async (url, options) => {
    const path = new URL(String(url)).pathname;
    if (path.includes('/bootstrap-proposals/'))
      return Response.json(++reads === 1 ? pending : fixture.consumed);
    if (path.endsWith('/bootstrap-metadata')) return Response.json(metadata);
    if (path.startsWith('/api/v1/approval-requests/')) return Response.json(approval);
    if (path.endsWith('/session/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
    expect(path).toBe('/v1/participants');
    expect(options?.method).toBe('POST');
    expect(JSON.parse(String(options?.body))).toEqual(fixture.review.candidate);
    const headers = new Headers(options?.headers);
    expect(headers.get('idempotency-key')).toBe(fixture.review.candidate.idempotencyKey);
    expect(headers.get('x-openpc-approval-request-id')).toBe(id(900));
    expect(headers.get('x-csrf-token')).toBe('c'.repeat(32));
    expect(headers.get('openpc-action-intent-digest')).toBe(fixture.review.actionIntentDigest);
    return Response.json({ accepted: true }); // Only the subsequent native readback establishes result.
  });
  const response = await fixture.run('COMMIT');
  expect(response.status).toBe(200);
  expect((await response.json()).operationId).toBe(fixture.operationId);
  expect(fetcher.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual([
    `/v1/participants/bootstrap-proposals/${fixture.review.candidate.participantId}/${encodeURIComponent(fixture.review.candidateDigest)}`,
    '/v1/participants/bootstrap-metadata',
    `/api/v1/approval-requests/${encodeURIComponent(approval.approvalRequestId)}`,
    '/api/v1/session/csrf',
    '/v1/participants',
    `/v1/participants/bootstrap-proposals/${fixture.review.candidate.participantId}/${encodeURIComponent(fixture.review.candidateDigest)}`,
  ]);
});
