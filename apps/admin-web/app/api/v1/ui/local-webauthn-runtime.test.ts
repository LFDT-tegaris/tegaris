import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { localFactAction } from '@openpc/ui-shell';
import { transactionKinds } from '../../../../lib/transaction-workflow';
import { transactionOperation } from './transaction-workbench-contract';

import { encodeBffSession, type IdentitySession } from './local-runtime';
import {
  beginLocalWebAuthnAssertion,
  completeLocalWebAuthnAssertion,
} from './local-webauthn-runtime';

let root = '';
const original = { ...process.env };
const session: IdentitySession = {
  sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000702',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000702',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PARTICIPANT',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const credentialId = '018f0000-0000-7000-8000-000000000711';
const externalCredentialId = 'AQIDBAUGBwgJCgsMDQ4PEA';
const challenge = 'assertion-challenge-value-00000000000000000001';
const stepUpActionIntentDigest = `sha256:${'7'.repeat(64)}`;
const approvalAction = {
  actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
  actionIntentDigest: 'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8',
  resourceId: '018f0000-0000-7000-8000-000000000301',
  resourceDigest: `sha256:${'a'.repeat(64)}`,
} as const;
const approvalResumeAction = {
  actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: 'sha256:dd2b80258905498007f0de87338d5044e8d7bb9b5d12d8336f28a67cdd9c2be9',
  resourceId: approvalAction.resourceId,
  resourceDigest: `sha256:${'b'.repeat(64)}`,
} as const;
const participantReadAction = {
  actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  actionIntentDigest: 'sha256:73a4a8e0cc469d63163715b94ce3882d4a66e86e3d7799cb7089dd3c5aff8ad0',
  resourceId: approvalAction.resourceId,
  resourceDigest: `sha256:${'c'.repeat(64)}`,
} as const;
const notificationEndpointActions = [
  {
    actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:5c86363197220c6ef9e4dfa653b551c758e2fd117276fa0fe8f2bdaa49a7ffc0',
    resourceId: approvalAction.resourceId,
    resourceDigest: approvalAction.resourceDigest,
  },
  {
    actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:8d3db9f82f631334222a946973f6ea8de29484f231b566a6bef0d16792b2a5ec',
    resourceId: approvalAction.resourceId,
    resourceDigest: approvalAction.resourceDigest,
  },
] as const;
const checkerActions = [
  approvalAction,
  participantReadAction,
  approvalResumeAction,
  {
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:c86183ee9e432405de0d145e007846fc9511a43bec274a055ad43b1ccbc207f9',
    resourceId: approvalAction.resourceId,
    resourceDigest: approvalAction.resourceDigest,
  },
  {
    actionIntentId: 'ACT-FLEET_RECOVER_OCCURRENCE-V1',
    actionIntentDigest: 'sha256:4dac3f1679a92c185899c5142e16f23d465b043112781f1686853a8e7679ab1d',
    resourceId: approvalAction.resourceId,
    resourceDigest: approvalAction.resourceDigest,
  },
  ...notificationEndpointActions,
  ...transactionKinds.map((kind) => {
    const operation = transactionOperation(kind);
    return {
      actionIntentId: operation.actionIntentId,
      actionIntentDigest: operation.actionIntentDigest,
      resourceId: approvalAction.resourceId,
      resourceDigest: approvalAction.resourceDigest,
    };
  }),
  {
    actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    actionIntentDigest: 'sha256:831ef2e7e3b05e92f8a950cfc4e8bdacb5463889654759aa1fd88c59da50513f',
    resourceId: credentialId,
    resourceDigest: `sha256:${'b'.repeat(64)}`,
  },
  {
    actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    actionIntentDigest: 'sha256:a3de751c7a68380154458c737a54b0d7de5328e33f83b8e37bd5ef610b2304c4',
    resourceId: '018f0000-0000-7000-8000-000000000305',
    resourceDigest: `sha256:${'e'.repeat(64)}`,
  },
  {
    actionIntentId: 'ACT-POLICY_ACTIVATE_PUBLISH-V1',
    actionIntentDigest: 'sha256:69027f899349c765077f9a9dfdc7868bb92c653a071347251d22c8bcf87c4edb',
    resourceId: '018f0000-0000-7000-8000-000000000302',
    resourceDigest: `sha256:${'b'.repeat(64)}`,
  },
  {
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    actionIntentDigest: 'sha256:6dd0e7edc1933d43beb79a0156559f9fc56f729fbc761cfb7770dd50bce8734c',
    resourceId: '018f0000-0000-7000-8000-000000000303',
    resourceDigest: `sha256:${'c'.repeat(64)}`,
  },
  {
    actionIntentId: 'ACT-POLICY_ROLLBACK_RELEASE-V1',
    actionIntentDigest: 'sha256:d5bc5ec3e43562a072ee107859df6803c0394add98d9e1837bf5b8074689914d',
    resourceId: '018f0000-0000-7000-8000-000000000304',
    resourceDigest: `sha256:${'d'.repeat(64)}`,
  },
] as const;
const contextAction = {
  actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
  actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
  resourceId: '018f0000-0000-7000-8000-000000000101',
  resourceDigest: 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700',
} as const;

function request(path: string, cookie: string, body: unknown, origin = 'http://127.0.0.1:8080') {
  return new NextRequest(`${origin}${path}`, {
    method: 'POST',
    headers: {
      'cookie': cookie,
      'host': new URL(origin).host,
      'origin': origin,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function responseCookie(response: Response, name: string): string {
  const value = new RegExp(`${name}=([^;,]+)`, 'u').exec(
    response.headers.get('set-cookie') ?? '',
  )?.[1];
  if (!value) throw new Error(`missing ${name}`);
  return `${name}=${value}`;
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-bff-webauthn-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie']) {
    await writeFile(join(root, name), name.repeat(32));
  }
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: 'http://gateway:8080',
    OPENPC_IDENTITY_INTERNAL_URL: 'http://identity:3001',
    OPENPC_FACT_INTERNAL_URL: 'http://fact:8081',
    OPENPC_POLICY_INTERNAL_URL: 'http://policy:3002',
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: 'http://127.0.0.1:53006/authorize',
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'identity'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'fact'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'policy'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...original };
  await rm(root, { recursive: true, force: true });
});

it('binds an opaque browser challenge to the owner action and live session revision', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(session))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
    .mockResolvedValueOnce(
      Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
    );
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const bffCookie = `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`;
  const response = await beginLocalWebAuthnAssertion(
    request('/api/v1/ui/webauthn/assertion/challenge', bffCookie, {
      actionIntentId: localFactAction.actionIntentId,
      actionIntentDigest: localFactAction.actionIntentDigest,
    }),
  );

  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    publicKey: {
      challenge,
      rpId: '127.0.0.1',
      allowCredentials: [
        { id: Buffer.from(credentialId).toString('base64url'), type: 'public-key' },
      ],
      timeout: 300_000,
      userVerification: 'required',
    },
  });
  const custody = responseCookie(response, 'openpc_webauthn_custody');
  expect(Buffer.from(custody.split('=')[1]!, 'base64url').toString('utf8')).not.toContain(
    session.sessionToken,
  );
  expect(fetchMock.mock.calls[2]?.[0]).toBe(
    'http://identity:3001/v1/identity/webauthn/assertion/challenge',
  );
  expect(fetchMock.mock.calls[2]?.[1]?.headers).toMatchObject({
    Cookie: `__Host-openpc_session=${session.sessionToken}`,
    Origin: 'http://identity:3001',
  });
  expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toMatchObject({
    actionIntentId: localFactAction.downstreamActionIntentId,
    resourceDigest: localFactAction.inputDigest,
  });
});

it.each(['http://127.0.0.1:8080', 'https://demo.example.org'])(
  'verifies a browser assertion through identity and confirms durable fresh readback (%s)',
  async (origin) => {
    const verifiedAt = new Date().toISOString();
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(session))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(
        Response.json({ challenge, credentialIds: [credentialId, externalCredentialId] }),
      )
      .mockResolvedValueOnce(
        Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
      );
    const cookieKey = Buffer.from('cookie'.repeat(32));
    const bffCookie = `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`;
    const started = await beginLocalWebAuthnAssertion(
      request(
        '/api/v1/ui/webauthn/assertion/challenge',
        bffCookie,
        {
          actionIntentId: localFactAction.actionIntentId,
          actionIntentDigest: localFactAction.actionIntentDigest,
        },
        origin,
      ),
    );
    expect(started.cookies.get('openpc_webauthn_custody')?.secure).toBe(
      origin.startsWith('https:'),
    );
    const custody = responseCookie(started, 'openpc_webauthn_custody');
    fetchMock
      .mockResolvedValueOnce(Response.json(session))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'd'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ status: 'verified' }))
      .mockResolvedValueOnce(Response.json({ ...session, stepUpVerifiedAt: verifiedAt }));

    const response = await completeLocalWebAuthnAssertion(
      request(
        '/api/v1/ui/webauthn/assertion/verify',
        `${bffCookie}; ${custody}`,
        {
          actionIntentId: localFactAction.actionIntentId,
          actionIntentDigest: localFactAction.actionIntentDigest,
          challenge,
          assertion: {
            credentialId: externalCredentialId,
            authenticatorData: 'YXV0aGVudGljYXRvcg',
            clientDataJson: 'Y2xpZW50LWRhdGE',
            signature: 'c2lnbmF0dXJl',
          },
        },
        origin,
      ),
    );

    expect(response.status).toBe(200);
    expect(response.cookies.get('openpc_webauthn_custody')?.secure).toBe(
      origin.startsWith('https:'),
    );
    expect(await response.json()).toEqual({
      status: 'verified',
      stepUpVerifiedAt: verifiedAt.replace(/\.(\d{3})Z$/u, '.$1000Z'),
    });
    const verification = fetchMock.mock.calls[6]!;
    expect(verification[0]).toBe('http://identity:3001/v1/identity/webauthn/assertion/verify');
    expect(verification[1]?.headers).toMatchObject({
      'Authorization': `Bearer ${'identity'.repeat(32)}`,
      'X-OpenPC-Browser-Origin': origin,
      'X-OpenPC-Aggregate-Version': '7',
      'OpenPC-Action-Intent-Digest': stepUpActionIntentDigest,
      'X-CSRF-Token': 'd'.repeat(43),
    });
    const ownerBody = JSON.parse(String(verification[1]?.body));
    expect(JSON.parse(ownerBody.assertion)).toMatchObject({
      credentialId: externalCredentialId,
    });
    expect(response.headers.get('set-cookie')).toContain('openpc_webauthn_custody=');
    expect(response.headers.get('set-cookie')).toContain('Max-Age=0');
  },
);

it('rejects challenge substitution before verification reaches the identity owner', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(session))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
    .mockResolvedValueOnce(
      Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
    );
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const bffCookie = `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`;
  const started = await beginLocalWebAuthnAssertion(
    request('/api/v1/ui/webauthn/assertion/challenge', bffCookie, {
      actionIntentId: localFactAction.actionIntentId,
      actionIntentDigest: localFactAction.actionIntentDigest,
    }),
  );
  const custody = responseCookie(started, 'openpc_webauthn_custody');
  fetchMock.mockResolvedValueOnce(Response.json(session));
  const response = await completeLocalWebAuthnAssertion(
    request('/api/v1/ui/webauthn/assertion/verify', `${bffCookie}; ${custody}`, {
      actionIntentId: localFactAction.actionIntentId,
      actionIntentDigest: localFactAction.actionIntentDigest,
      challenge: `${challenge}x`,
      assertion: {
        credentialId: Buffer.from(credentialId).toString('base64url'),
        authenticatorData: 'YQ',
        clientDataJson: 'Yg',
        signature: 'Yw',
      },
    }),
  );
  expect(response.status).toBe(403);
  expect(fetchMock).toHaveBeenCalledTimes(5);
});

it.each([
  ['approval resume', approvalResumeAction],
  ['administrator handoff READ', participantReadAction],
] as const)(
  'preserves the %s purpose through native verification in Platform context',
  async (_purpose, action) => {
    const actor = { ...session, contextMode: 'PLATFORM' as const, privacyDomainId: undefined };
    const verifiedAt = new Date().toISOString();
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [externalCredentialId] }))
      .mockResolvedValueOnce(
        Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
      );
    const cookieKey = Buffer.from('cookie'.repeat(32));
    const bffCookie = `openpc_local_runtime_session=${encodeBffSession(actor, cookieKey)}`;
    const started = await beginLocalWebAuthnAssertion(
      request('/api/v1/ui/webauthn/assertion/challenge', bffCookie, action),
    );
    expect(started.status).toBe(200);
    const custody = responseCookie(started, 'openpc_webauthn_custody');
    fetchMock
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'd'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ status: 'verified' }))
      .mockResolvedValueOnce(Response.json({ ...actor, stepUpVerifiedAt: verifiedAt }));
    const verified = await completeLocalWebAuthnAssertion(
      request('/api/v1/ui/webauthn/assertion/verify', `${bffCookie}; ${custody}`, {
        ...action,
        challenge,
        assertion: {
          credentialId: externalCredentialId,
          authenticatorData: 'YQ',
          clientDataJson: 'Yg',
          signature: 'Yw',
        },
      }),
    );
    expect(verified.status).toBe(200);
    for (const index of [2, 6]) {
      expect(JSON.parse(String(fetchMock.mock.calls[index]?.[1]?.body))).toMatchObject({
        actionIntentId: action.actionIntentId,
        resourceId: action.resourceId,
        resourceDigest: action.resourceDigest,
      });
    }
    expect(fetchMock).toHaveBeenCalledTimes(8);
    expect(verified.headers.get('set-cookie')).toContain('Max-Age=0');
  },
);

it('forwards exact governed bindings for either authenticated presentation profile', async () => {
  const cookieKey = Buffer.from('cookie'.repeat(32));
  for (const role of ['operator', 'viewer'] as const) {
    for (const action of checkerActions) {
      vi.restoreAllMocks();
      const actor = { ...session, role };
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(Response.json(actor))
        .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
        .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
        .mockResolvedValueOnce(
          Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
        );
      const admitted = await beginLocalWebAuthnAssertion(
        request(
          '/api/v1/ui/webauthn/assertion/challenge',
          `openpc_local_runtime_session=${encodeBffSession(actor, cookieKey)}`,
          action,
        ),
      );
      expect(admitted.status).toBe(200);
      expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toEqual({
        actionIntentId: action.actionIntentId,
        resourceId: action.resourceId,
        resourceDigest: action.resourceDigest,
        rpIdHash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
      });
    }
  }
});

it('preserves the Identity owner’s governance denial without creating a custody receipt', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(session))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1002' } }, { status: 403 }));
  const denied = await beginLocalWebAuthnAssertion(
    request(
      '/api/v1/ui/webauthn/assertion/challenge',
      `openpc_local_runtime_session=${encodeBffSession(session, Buffer.from('cookie'.repeat(32)))}`,
      approvalAction,
    ),
  );
  expect(denied.status).toBe(403);
  expect(denied.headers.get('set-cookie')).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it('rejects transaction digest substitution and missing candidate bindings before challenge dispatch', async () => {
  const cookieKey = Buffer.from('cookie'.repeat(32));
  for (const action of [
    approvalResumeAction,
    participantReadAction,
    {
      actionIntentId: 'ACT-FLEET_RECOVER_OCCURRENCE-V1',
      actionIntentDigest: 'sha256:4dac3f1679a92c185899c5142e16f23d465b043112781f1686853a8e7679ab1d',
      resourceId: approvalAction.resourceId,
      resourceDigest: approvalAction.resourceDigest,
    },
    ...notificationEndpointActions,
    ...transactionKinds.map((kind) => {
      const operation = transactionOperation(kind);
      return {
        actionIntentId: operation.actionIntentId,
        actionIntentDigest: operation.actionIntentDigest,
        resourceId: approvalAction.resourceId,
        resourceDigest: approvalAction.resourceDigest,
      };
    }),
  ]) {
    for (const input of [
      { ...action, actionIntentDigest: approvalAction.actionIntentDigest },
      { ...action, resourceId: undefined },
      { ...action, resourceDigest: undefined },
    ]) {
      vi.restoreAllMocks();
      const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(session));
      const denied = await beginLocalWebAuthnAssertion(
        request(
          '/api/v1/ui/webauthn/assertion/challenge',
          `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
          input,
        ),
      );
      expect(denied.status).toBe(400);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(denied.headers.get('set-cookie')).toBeNull();
    }
  }
});

it.each([
  ['session', { sessionId: '018f0000-0000-7000-8000-000000000703' }, {}],
  ['principal', { principalId: '018f0000-0000-7000-8000-000000000112' }, {}],
  ['context', { contextEpoch: '3' }, {}],
  ['Participant', { participantId: '018f0000-0000-7000-8000-000000000102' }, {}],
  ['privacy domain', { privacyDomainId: '018f0000-0000-7000-8000-000000000202' }, {}],
  ['resource', {}, { resourceId: credentialId }],
  ['digest', {}, { resourceDigest: `sha256:${'f'.repeat(64)}` }],
])(
  'rejects %s substitution before sending an assertion to Identity',
  async (_name, sessionChange, actionChange) => {
    for (const action of [
      approvalAction,
      approvalResumeAction,
      participantReadAction,
      ...notificationEndpointActions,
    ]) {
      vi.restoreAllMocks();
      const fetchMock = vi
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(Response.json(session))
        .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
        .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
        .mockResolvedValueOnce(
          Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
        );
      const cookieKey = Buffer.from('cookie'.repeat(32));
      const bffCookie = `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`;
      const started = await beginLocalWebAuthnAssertion(
        request('/api/v1/ui/webauthn/assertion/challenge', bffCookie, action),
      );
      expect(started.status).toBe(200);
      const custody = responseCookie(started, 'openpc_webauthn_custody');
      const changed = { ...session, ...sessionChange };
      fetchMock.mockResolvedValueOnce(Response.json(changed));
      const denied = await completeLocalWebAuthnAssertion(
        request(
          '/api/v1/ui/webauthn/assertion/verify',
          `openpc_local_runtime_session=${encodeBffSession(changed, cookieKey)}; ${custody}`,
          {
            ...action,
            ...actionChange,
            challenge,
            assertion: {
              credentialId: Buffer.from(credentialId).toString('base64url'),
              authenticatorData: 'YQ',
              clientDataJson: 'Yg',
              signature: 'Yw',
            },
          },
        ),
      );
      expect(denied.status).toBe(403);
      expect(fetchMock).toHaveBeenCalledTimes(5);
    }
  },
);

it('allows either authenticated role to step up the exact Participant-context transition', async () => {
  for (const role of ['operator', 'viewer'] as const) {
    vi.restoreAllMocks();
    const actor = { ...session, role };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
      .mockResolvedValueOnce(
        Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
      );
    const cookieKey = Buffer.from('cookie'.repeat(32));
    const response = await beginLocalWebAuthnAssertion(
      request(
        '/api/v1/ui/webauthn/assertion/challenge',
        `openpc_local_runtime_session=${encodeBffSession(actor, cookieKey)}`,
        contextAction,
      ),
    );
    expect(response.status).toBe(200);
    expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toMatchObject({
      actionIntentId: contextAction.actionIntentId,
      resourceId: contextAction.resourceId,
      resourceDigest: contextAction.resourceDigest,
    });
  }
});

it('admits the exact principal provision binding and rejects substituted digests', async () => {
  const action = {
    actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    actionIntentDigest: 'sha256:831ef2e7e3b05e92f8a950cfc4e8bdacb5463889654759aa1fd88c59da50513f',
    resourceId: credentialId,
    resourceDigest: `sha256:${'b'.repeat(64)}`,
  };
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(session))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
    .mockResolvedValueOnce(
      Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
    );
  const admitted = await beginLocalWebAuthnAssertion(
    request(
      '/api/v1/ui/webauthn/assertion/challenge',
      `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
      action,
    ),
  );
  expect(admitted.status).toBe(200);
  expect(JSON.parse(String(fetch.mock.calls[2]?.[1]?.body))).toMatchObject({
    actionIntentId: action.actionIntentId,
    resourceId: action.resourceId,
    resourceDigest: action.resourceDigest,
  });
  for (const [actor, input, status] of [
    [session, { ...action, actionIntentDigest: `sha256:${'f'.repeat(64)}` }, 400],
  ] as const) {
    vi.restoreAllMocks();
    const deniedFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(actor));
    const denied = await beginLocalWebAuthnAssertion(
      request(
        '/api/v1/ui/webauthn/assertion/challenge',
        `openpc_local_runtime_session=${encodeBffSession(actor, cookieKey)}`,
        input,
      ),
    );
    expect(denied.status).toBe(status);
    expect(deniedFetch).toHaveBeenCalledTimes(1);
  }
});

it.each(['ACT-PARTICIPANTS_CREATE_RESOURCE-V1', 'ACT-IDENTITY_UPDATE_STEP_UP-V1'])(
  'binds Platform %s WebAuthn to registered backend metadata',
  async (actionIntentId) => {
    const actor = {
      ...session,
      contextMode: 'PLATFORM' as const,
      privacyDomainId: undefined,
      platformBootstrapEligible: true,
    };
    const meta = {
      participantId: actor.participantId,
      privacyDomainId: session.privacyDomainId,
      actionIntentDigest: `sha256:${'8'.repeat(64)}`,
      stepUpActionIntentDigest,
    };
    const action = {
      actionIntentId,
      actionIntentDigest:
        actionIntentId === 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1'
          ? meta.actionIntentDigest
          : meta.stepUpActionIntentDigest,
      resourceId:
        actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1' ? actor.sessionId : credentialId,
      resourceDigest: `sha256:${'a'.repeat(64)}`,
    };
    const cookie = `openpc_local_runtime_session=${encodeBffSession(actor, Buffer.from('cookie'.repeat(32)))}`;
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(Response.json(meta))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ challenge, credentialIds: [credentialId] }))
      .mockResolvedValueOnce(
        Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
      );
    expect(
      (
        await beginLocalWebAuthnAssertion(
          request('/api/v1/ui/webauthn/assertion/challenge', cookie, action),
        )
      ).status,
    ).toBe(200);
    expect(JSON.parse(String(fetcher.mock.calls[3]?.[1]?.body))).toMatchObject({
      actionIntentId,
      resourceId: action.resourceId,
      resourceDigest: action.resourceDigest,
    });
    for (const metadata of [
      { ...meta, participantId: credentialId },
      {
        ...meta,
        actionIntentDigest: `sha256:${'f'.repeat(64)}`,
        stepUpActionIntentDigest: `sha256:${'f'.repeat(64)}`,
      },
    ]) {
      fetcher
        .mockResolvedValueOnce(Response.json(actor))
        .mockResolvedValueOnce(Response.json(metadata));
      const before = fetcher.mock.calls.length;
      expect(
        (
          await beginLocalWebAuthnAssertion(
            request('/api/v1/ui/webauthn/assertion/challenge', cookie, action),
          )
        ).status,
      ).toBeGreaterThanOrEqual(400);
      expect(fetcher.mock.calls.length).toBe(before + 2);
    }
  },
);

it.each(['legacy', 'normal-owner', 'LOCAL_QA_10X'] as const)(
  'pins owner challenge expiry and never extends legacy custody after enabling QA (%s)',
  async (mode) => {
    const durationProfile = mode === 'LOCAL_QA_10X' ? mode : undefined;
    const deadlineMs = mode === 'normal-owner' ? 30000 : durationProfile ? 3000000 : 300000;
    const issuedAt = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(issuedAt);
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(session))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(
        Response.json({
          challenge,
          credentialIds: [externalCredentialId],
          ...(mode !== 'legacy'
            ? { expiresAt: new Date(issuedAt + deadlineMs).toISOString() }
            : {}),
          ...(durationProfile ? { durationProfile } : {}),
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ revision: '7', actionIntentDigest: stepUpActionIntentDigest }),
      );
    const bffCookie = `openpc_local_runtime_session=${encodeBffSession(session, Buffer.from('cookie'.repeat(32)))}`;
    const started = await beginLocalWebAuthnAssertion(
      request('/api/v1/ui/webauthn/assertion/challenge', bffCookie, {
        actionIntentId: localFactAction.actionIntentId,
        actionIntentDigest: localFactAction.actionIntentDigest,
      }),
    );
    expect(started.status).toBe(200);
    const body = await started.json();
    expect(body.publicKey.timeout).toBe(deadlineMs);
    expect(Date.parse(body.expiresAt)).toBe(issuedAt + deadlineMs);
    const custody = responseCookie(started, 'openpc_webauthn_custody');
    Object.assign(process.env, {
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
    });
    clock.mockReturnValue(issuedAt + deadlineMs);
    fetcher.mockResolvedValueOnce(Response.json(session));
    const denied = await completeLocalWebAuthnAssertion(
      request('/api/v1/ui/webauthn/assertion/verify', `${bffCookie}; ${custody}`, {
        actionIntentId: localFactAction.actionIntentId,
        actionIntentDigest: localFactAction.actionIntentDigest,
        challenge,
        assertion: {
          credentialId: externalCredentialId,
          authenticatorData: 'YXV0aGVudGljYXRvcg',
          clientDataJson: 'Y2xpZW50LWRhdGE',
          signature: 'c2lnbmF0dXJl',
        },
      }),
    );
    expect(denied.status).toBeGreaterThanOrEqual(400);
    expect(fetcher).toHaveBeenCalledTimes(5);
  },
);
