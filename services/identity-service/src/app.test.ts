import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildIdentityService, type IdentityAuthorizationAdapter } from './app.js';
import { IdentityKernel } from './domain/identity-kernel.js';
import {
  createVerifiedWebAuthnAssertion,
  type IdentityTrustAdapter,
} from './domain/trust-adapter.js';

const sessionToken = '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000117';
const actionIntentId = 'ACT-POLICY_APPROVE_REQUEST-V1';
const resourceId = '018f0000-0000-7000-8000-000000000913';
const resourceDigest = `sha256:${'a'.repeat(64)}`;
const rpIdHash = `sha256:${'b'.repeat(64)}`;
const origin = 'https://control.openpc.example';

function kernelFixture() {
  const sessionSnapshot = vi.fn(async () => ({
    sessionId: '018f0000-0000-7000-8000-000000000117',
    sessionToken,
    principalId: '018f0000-0000-7000-8000-000000000114',
    participantId: '018f0000-0000-7000-8000-000000000101',
    participantEpoch: '5',
    authorityEpoch: '5',
    sessionEpoch: '1',
    refreshFamilyId: '018f0000-0000-7000-8000-000000000118',
    state: 'ACTIVE' as const,
    issuedAt: new Date('2026-09-11T00:00:00Z'),
    lastSeenAt: new Date('2026-09-11T00:00:00Z'),
    idleExpiresAt: new Date('2026-09-11T00:30:00Z'),
    absoluteExpiresAt: new Date('2026-09-11T12:00:00Z'),
  }));
  const verifyCsrf = vi.fn(async () => undefined);
  const issueStepUpAssertionChallenge = vi.fn(async () => ({
    challenge: 'assertion-challenge-value-00000000000000000001',
    credentialIds: ['018f0000-0000-7000-8000-000000000916'],
  }));
  const kernel = {
    sessionSnapshot,
    verifyCsrf,
    issueStepUpAssertionChallenge,
  } as unknown as IdentityKernel;
  return { kernel, sessionSnapshot, verifyCsrf, issueStepUpAssertionChallenge };
}

function challengeRequest(csrfToken = 'csrf-token-value-0000000000000001') {
  return {
    method: 'POST' as const,
    url: '/v1/identity/webauthn/assertion/challenge',
    headers: {
      'cookie': `__Host-openpc_session=${sessionToken}`,
      origin,
      'host': 'control.openpc.example',
      'x-csrf-token': csrfToken,
    },
    payload: { actionIntentId, resourceId, resourceDigest, rpIdHash },
  };
}

afterEach(() => vi.restoreAllMocks());

describe('WebAuthn assertion challenge admission', () => {
  it('selects the context-entry catalogue operation for the authenticated Participant', async () => {
    const fixture = kernelFixture();
    const authorize = vi.fn(
      async (input: Parameters<IdentityAuthorizationAdapter['authorize']>[0]) => ({
        allowed: input.catalogOperationId === 'ID-OP-SESSION-CONTEXT-SELECT',
      }),
    );
    const app = buildIdentityService(fixture.kernel, undefined, undefined, { authorize });
    const request = challengeRequest();
    const response = await app.inject({
      ...request,
      payload: {
        ...request.payload,
        actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        resourceId: sessionToken.split('.')[0],
      },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
        actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        resourceId: sessionToken.split('.')[0],
        makerCheckerRequired: false,
        stepUpRequired: false,
      }),
    );
    expect(fixture.issueStepUpAssertionChallenge).toHaveBeenCalledOnce();
    await app.close();
  });

  it.each([
    ['ACT-IDENTITY_CREATE_SESSION-V1', '018f0000-0000-7000-8000-000000000999'],
    ['ACT-IDENTITY_CREATE_SESSION-V1', sessionToken.split('.')[1]],
    ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', sessionToken.split('.')[0]],
  ])('does not lend context-entry admission to %s on %s', async (intent, resource) => {
    const fixture = kernelFixture();
    const authorize = vi.fn(
      async (input: Parameters<IdentityAuthorizationAdapter['authorize']>[0]) => ({
        allowed: input.catalogOperationId === 'ID-OP-SESSION-CONTEXT-SELECT',
      }),
    );
    const app = buildIdentityService(fixture.kernel, undefined, undefined, { authorize });
    const request = challengeRequest();
    const response = await app.inject({
      ...request,
      payload: {
        ...request.payload,
        actionIntentId: intent,
        resourceId: resource,
      },
    });
    expect(response.statusCode).not.toBe(200);
    expect(authorize).toHaveBeenCalledOnce();
    expect(authorize.mock.calls[0]![0].catalogOperationId).toBeUndefined();
    expect(fixture.issueStepUpAssertionChallenge).not.toHaveBeenCalled();
    await app.close();
  });

  it('binds CSRF and live target authorization before issuing a challenge', async () => {
    const fixture = kernelFixture();
    const authorize = vi.fn(async () => ({ allowed: true }));
    const app = buildIdentityService(fixture.kernel, undefined, undefined, {
      authorize,
    } satisfies IdentityAuthorizationAdapter);

    const response = await app.inject(challengeRequest());

    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toEqual({
      challenge: 'assertion-challenge-value-00000000000000000001',
      credentialIds: ['018f0000-0000-7000-8000-000000000916'],
    });
    expect(fixture.verifyCsrf).toHaveBeenCalledWith(
      sessionToken,
      actionIntentId,
      origin,
      'control.openpc.example',
      'csrf-token-value-0000000000000001',
    );
    expect(authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        actionIntentId,
        resourceId,
        makerCheckerRequired: false,
        stepUpRequired: false,
      }),
    );
    expect(fixture.issueStepUpAssertionChallenge).toHaveBeenCalledWith(
      sessionToken,
      actionIntentId,
      resourceDigest,
      rpIdHash,
      resourceId,
    );
    await app.close();
  });

  it('rejects missing CSRF without authenticating, authorizing, or issuing state', async () => {
    const fixture = kernelFixture();
    const authorize = vi.fn(async () => ({ allowed: true }));
    const app = buildIdentityService(fixture.kernel, undefined, undefined, {
      authorize,
    } satisfies IdentityAuthorizationAdapter);
    const request = challengeRequest();
    const headersWithoutCsrf = Object.fromEntries(
      Object.entries(request.headers).filter(([name]) => name !== 'x-csrf-token'),
    );

    const response = await app.inject({ ...request, headers: headersWithoutCsrf });

    expect(response.statusCode).toBe(401);
    expect(fixture.sessionSnapshot).not.toHaveBeenCalled();
    expect(authorize).not.toHaveBeenCalled();
    expect(fixture.issueStepUpAssertionChallenge).not.toHaveBeenCalled();
    await app.close();
  });

  it('fails closed when current target authority is absent', async () => {
    const fixture = kernelFixture();
    const app = buildIdentityService(fixture.kernel, undefined, undefined, {
      async authorize() {
        return { allowed: false };
      },
    });

    const response = await app.inject(challengeRequest());

    expect(response.statusCode).toBe(409);
    expect(fixture.issueStepUpAssertionChallenge).not.toHaveBeenCalled();
    await app.close();
  });

  it('carries the exact context-selection target into step-up mutation authorization', async () => {
    const fixture = kernelFixture();
    const actionDigest = `sha256:${'c'.repeat(64)}`;
    const verifyStepUp = vi.fn(async () => undefined);
    const kernel = {
      ...fixture.kernel,
      actionIntentSemanticDigest: vi.fn(async () => actionDigest),
      verifyStepUp,
    } as unknown as IdentityKernel;
    const authorize = vi.fn(
      async (input: Parameters<IdentityAuthorizationAdapter['authorize']>[0]) =>
        input.actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1'
          ? {
              allowed: true,
              evidenceKind: 'IDENTITY_RUNTIME' as const,
              signerKeyDigest: Buffer.alloc(32, 1),
              privacyDomainId: '018f0000-0000-7000-8000-000000000201',
              evidenceCbor: Buffer.from('evidence'),
              evidenceDigest: Buffer.alloc(32, 2),
              coseSign1: Buffer.from('signature'),
            }
          : { allowed: true },
    );
    const verified = createVerifiedWebAuthnAssertion({
      credentialId: '018f0000-0000-7000-8000-000000000916',
      credentialPublicKeyDigest: `sha256:${'d'.repeat(64)}`,
      principalId: '018f0000-0000-7000-8000-000000000114',
      sessionId: '018f0000-0000-7000-8000-000000000117',
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      resourceDigest,
      challengeDigest: `sha256:${'e'.repeat(64)}`,
      rpIdHash,
      origin,
      authenticatorDataDigest: `sha256:${'1'.repeat(64)}`,
      clientDataJsonDigest: `sha256:${'2'.repeat(64)}`,
      signatureDigest: `sha256:${'3'.repeat(64)}`,
      signCount: '1',
      verifiedAt: '2026-09-11T00:00:00.000Z',
    });
    const trustAdapter = {
      async exchangeAuthorizationCode() {
        return undefined;
      },
      async verifyWebAuthnAssertion() {
        return verified;
      },
    } satisfies IdentityTrustAdapter;
    const app = buildIdentityService(kernel, trustAdapter, undefined, { authorize });

    const response = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/assertion/verify',
      headers: {
        'cookie': `__Host-openpc_session=${sessionToken}`,
        origin,
        'host': 'control.openpc.example',
        'x-csrf-token': 'csrf-token-value-0000000000000001',
        'openpc-action-intent-digest': actionDigest,
        'x-openpc-aggregate-version': '1',
        'idempotency-key': 'context-step-up-test-key',
      },
      payload: {
        actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        resourceId: '018f0000-0000-7000-8000-000000000101',
        resourceDigest,
        rpIdHash,
        challenge: 'assertion-challenge-value-00000000000000000001',
        assertion: 'verified-assertion-input',
      },
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(authorize).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
        resourceId: '018f0000-0000-7000-8000-000000000101',
      }),
    );
    expect(authorize).toHaveBeenLastCalledWith(
      expect.objectContaining({
        actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        stepUpTargetActionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
        stepUpTargetResourceId: '018f0000-0000-7000-8000-000000000101',
      }),
    );
    expect(verifyStepUp).toHaveBeenCalledOnce();
    await app.close();
  });
});
