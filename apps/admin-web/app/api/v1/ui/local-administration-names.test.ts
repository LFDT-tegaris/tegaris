import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { reserveAdministrationName, readAdministrationNames } from './local-administration-names';
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
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const actor: IdentitySession = {
  sessionToken: 'private-unit-session',
  role: 'operator',
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const runtime: LocalConfig = {
  publicApiUrl: 'http://owner.invalid',
  identityUrl: 'http://identity.invalid',
  policyUrl: 'http://policy.invalid',
  factUrl: 'http://fact.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'private-identity',
  policyToken: 'private-policy',
  factToken: 'private-fact',
  cookieKey: randomBytes(64),
};
const binding = {
  purpose: 'APPROVAL_REQUEST',
  businessActionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  businessResourceId: id(5),
  expectedBusinessRevision: '0',
  checkerPrincipalId: id(6),
};
const result = () => ({
  ...binding,
  kind: 'ADMINISTRATION_RESOURCE_NAME',
  version: 1,
  operationId: id(7),
  reservedResourceId: id(8),
  participantId: actor.participantId,
  privacyDomainId: actor.privacyDomainId,
  makerPrincipalId: actor.principalId,
  createdAt: new Date().toISOString(),
  validUntil: new Date(Date.now() + 3600000).toISOString(),
  authorityEffect: 'NONE',
  requiresFreshAuthority: true,
});
const request = (body?: unknown, query = '') =>
  new NextRequest(`http://localhost:8080/api/v1/ui/administration-names${query}`, {
    method: body ? 'POST' : 'GET',
    headers: {
      'host': 'localhost:8080',
      'origin': 'http://localhost:8080',
      'content-type': 'application/json',
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
let reservation: ReturnType<typeof result> & { predecessorOperationId?: string } = result();
beforeEach(() => {
  reservation = result();
  vi.mocked(authenticated).mockResolvedValue(actor);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).endsWith('/session/csrf') ? { csrfToken: 'a'.repeat(43) } : reservation,
    ),
  );
});
afterEach(() => vi.restoreAllMocks());
it('binds durable allocation to the actual maker and exact business intent with stable replay', async () => {
  const input = { command: 'RESERVE', requestKey: id(9), ...binding };
  for (let n = 0; n < 2; n++)
    expect((await reserveAdministrationName(request(input))).status).toBe(201);
  const calls = vi
    .mocked(fetch)
    .mock.calls.filter(([url]) => String(url).endsWith('/administration-resource-reservations'));
  expect(calls).toHaveLength(2);
  expect(JSON.parse(String(calls[0]?.[1]?.body))).toMatchObject({
    ...binding,
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
  });
  expect(new Headers(calls[0]?.[1]?.headers).get('idempotency-key')).toBe(
    new Headers(calls[1]?.[1]?.headers).get('idempotency-key'),
  );
});
it('rejects expired or mismatched owner readback and foreign namespace', async () => {
  for (const changed of [
    { ...result(), validUntil: new Date(Date.now() - 1000).toISOString() },
    { ...result(), businessResourceId: id(99) },
  ]) {
    reservation = changed;
    expect(
      (
        await reserveAdministrationName(
          request({ command: 'RESERVE', requestKey: id(9), ...binding }),
        )
      ).status,
    ).toBe(503);
  }
  reservation = { ...result(), privacyDomainId: id(99) };
  expect((await readAdministrationNames(request(undefined, `?operationId=${id(7)}`))).status).toBe(
    404,
  );
});
it('rejects extra authority fields before creating a name', async () => {
  expect(
    (
      await reserveAdministrationName(
        request({
          command: 'RESERVE',
          requestKey: id(9),
          ...binding,
          capabilityIds: ['CALL_RESULT_DISCLOSURE'],
        }),
      )
    ).status,
  ).toBe(400);
  expect(vi.mocked(fetch)).not.toHaveBeenCalled();
});

it('carries the exact expired predecessor and rejects mismatched successor readback', async () => {
  const input = {
    command: 'RESERVE',
    requestKey: id(9),
    ...binding,
    predecessorOperationId: id(10),
  };
  reservation = { ...result(), predecessorOperationId: id(10) };
  expect((await reserveAdministrationName(request(input))).status).toBe(201);
  const call = vi
    .mocked(fetch)
    .mock.calls.find(([url]) => String(url).endsWith('/administration-resource-reservations'));
  expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
    predecessorOperationId: id(10),
    ...binding,
  });
  reservation = { ...result(), predecessorOperationId: id(11) };
  expect((await reserveAdministrationName(request(input))).status).toBe(503);
});
