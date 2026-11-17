import { describe, expect, it, vi } from 'vitest';

import { buildIdentityService } from './app.js';
import { IdentityKernel } from './domain/identity-kernel.js';
import type { WebAuthnRegistrationAdapter } from './domain/webauthn-registration.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000117';
const nextSessionId = '018f0000-0000-7000-8000-000000000118';
const enrollmentId = '018f0000-0000-7000-8000-000000000119';
const replacedCredentialId = '018f0000-0000-7000-8000-000000000121';
const replacementEnrollmentId = '018f0000-0000-7000-8000-000000000122';
const sessionToken = `${participantId}.${sessionId}`;
const nextSessionToken = `${participantId}.${nextSessionId}`;
const origin = 'https://control.openpc.example';
const actionIntentDigest = `sha256:${'a'.repeat(64)}`;

function snapshot(token = sessionToken) {
  return {
    sessionId: token === sessionToken ? sessionId : nextSessionId,
    sessionToken: token,
    principalId,
    participantId,
    contextMode: token === sessionToken ? ('PLATFORM' as const) : ('PARTICIPANT' as const),
    ...(token === sessionToken ? {} : { privacyDomainId }),
    contextEpoch: token === sessionToken ? '1' : '2',
    participantEpoch: '5',
    authorityEpoch: '7',
    sessionEpoch: token === sessionToken ? '1' : '2',
    refreshFamilyId: '018f0000-0000-7000-8000-000000000120',
    state: 'ACTIVE' as const,
    issuedAt: new Date('2026-09-12T00:00:00Z'),
    lastSeenAt: new Date('2026-09-12T00:00:00Z'),
    idleExpiresAt: new Date('2026-09-12T00:30:00Z'),
    absoluteExpiresAt: new Date('2026-09-12T12:00:00Z'),
  };
}

function fixture() {
  const sessionSnapshot = vi.fn(async () => snapshot());
  const actionIntentSemanticDigest = vi.fn(async () => actionIntentDigest);
  const verifyCsrf = vi.fn(async () => undefined);
  const beginInitialWebAuthnEnrollment = vi.fn(async () => ({
    enrollmentId,
    challenge: 'registration-challenge-value-00000000000001',
    rpId: 'control.openpc.example',
    origin,
    principalId,
    displayLabel: 'Initial operator',
    excludedCredentialIds: [],
    expiresAt: new Date('2026-09-12T00:05:00Z'),
  }));
  const initialWebAuthnEnrollmentContext = vi.fn(async () => ({
    expectedChallengeDigest: Buffer.alloc(32, 1),
    expectedOrigin: origin,
    expectedRpId: 'control.openpc.example',
  }));
  const completeInitialWebAuthnEnrollment = vi.fn(async () => ({
    credentialId: replacedCredentialId,
    externalCredentialId: 'registered-credential',
    credentialEpoch: '1',
    state: 'ACTIVE' as const,
  }));
  const beginReplacementWebAuthnEnrollment = vi.fn(async () => ({
    enrollmentId: replacementEnrollmentId,
    challenge: 'replacement-challenge-value-000000000000001',
    rpId: 'control.openpc.example',
    origin,
    principalId,
    displayLabel: 'Initial operator',
    excludedCredentialIds: ['registered-credential'],
    expiresAt: new Date('2026-09-12T00:05:00Z'),
    replacedCredentialId,
  }));
  const replacementWebAuthnEnrollmentContext = vi.fn(async () => ({
    expectedChallengeDigest: Buffer.alloc(32, 1),
    expectedOrigin: origin,
    expectedRpId: 'control.openpc.example',
    replacedCredentialId,
  }));
  const webAuthnCredentialAggregateVersion = vi.fn(async () => '4');
  const completeReplacementWebAuthnEnrollment = vi.fn(async () => ({
    credentialId: '018f0000-0000-7000-8000-000000000123',
    externalCredentialId: 'registered-credential-replacement',
    credentialEpoch: '2',
    state: 'ACTIVE' as const,
  }));
  const selectParticipantContext = vi.fn(async () => snapshot(nextSessionToken));
  const kernel = {
    sessionSnapshot,
    actionIntentSemanticDigest,
    verifyCsrf,
    beginInitialWebAuthnEnrollment,
    initialWebAuthnEnrollmentContext,
    completeInitialWebAuthnEnrollment,
    beginReplacementWebAuthnEnrollment,
    replacementWebAuthnEnrollmentContext,
    webAuthnCredentialAggregateVersion,
    completeReplacementWebAuthnEnrollment,
    selectParticipantContext,
  } as unknown as IdentityKernel;
  const registration: WebAuthnRegistrationAdapter = {
    options: vi.fn(async (input) => ({ challenge: input.challenge, rp: { id: input.rpId } })),
    verify: vi.fn(async () => ({
      externalCredentialId: 'registered-credential',
      publicKeySpkiDer: Buffer.alloc(91, 2),
      publicKeyDigest: Buffer.alloc(32, 3),
      signCount: '0',
      attestationDigest: Buffer.alloc(32, 4),
    })),
  };
  return {
    kernel,
    registration,
    sessionSnapshot,
    actionIntentSemanticDigest,
    verifyCsrf,
    beginInitialWebAuthnEnrollment,
    initialWebAuthnEnrollmentContext,
    completeInitialWebAuthnEnrollment,
    beginReplacementWebAuthnEnrollment,
    replacementWebAuthnEnrollmentContext,
    webAuthnCredentialAggregateVersion,
    completeReplacementWebAuthnEnrollment,
    selectParticipantContext,
  };
}

const headers = {
  'cookie': `__Host-openpc_session=${sessionToken}`,
  origin,
  'host': 'control.openpc.example',
  'x-csrf-token': 'csrf-token',
};

describe('initial trust and context HTTP boundary', () => {
  it('keeps the challenge server-bound and completes only verified registration output', async () => {
    const f = fixture();
    const app = buildIdentityService(
      f.kernel,
      undefined,
      undefined,
      undefined,
      undefined,
      f.registration,
    );
    const options = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/initial-registration/options',
      headers,
      payload: {},
    });
    expect(options.statusCode, options.body).toBe(201);
    expect(options.json()).toMatchObject({
      enrollmentId,
      publicKey: { rp: { id: 'control.openpc.example' } },
    });
    expect(options.body).not.toContain('expectedChallengeDigest');

    const completed = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/initial-registration/complete',
      headers,
      payload: { enrollmentId, response: { id: 'browser-owned' } },
    });
    expect(completed.statusCode, completed.body).toBe(201);
    expect(f.initialWebAuthnEnrollmentContext).toHaveBeenCalledWith(sessionToken, enrollmentId);
    expect(f.registration.verify).toHaveBeenCalledWith(
      expect.objectContaining({
        response: { id: 'browser-owned' },
        expectedOrigin: origin,
        expectedRpId: 'control.openpc.example',
      }),
    );
    expect(f.completeInitialWebAuthnEnrollment).toHaveBeenCalledWith(
      sessionToken,
      enrollmentId,
      expect.objectContaining({ externalCredentialId: 'registered-credential' }),
    );
    await app.close();
  });

  it('rotates the cookie when selecting an explicit Participant/privacy context', async () => {
    const f = fixture();
    const app = buildIdentityService(f.kernel);
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/session/context',
      headers,
      payload: { participantId, privacyDomainId },
    });
    expect(response.statusCode, response.body).toBe(201);
    expect(response.headers['set-cookie']).toContain(nextSessionToken);
    expect(response.json()).toMatchObject({
      contextMode: 'PARTICIPANT',
      participantId,
      privacyDomainId,
      contextEpoch: '2',
    });
    expect(f.selectParticipantContext).toHaveBeenCalledWith(sessionToken, {
      participantId,
      privacyDomainId,
    });
    await app.close();
  });

  it('binds replacement to the authenticated browser origin while retaining service-origin CSRF', async () => {
    const f = fixture();
    const internalHeaders = {
      ...headers,
      origin: 'http://identity-service:3001',
      host: 'identity-service:3001',
    };
    const app = buildIdentityService(
      f.kernel,
      undefined,
      undefined,
      undefined,
      () => origin,
      f.registration,
    );
    const options = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/options',
      headers: internalHeaders,
      payload: { replacedCredentialId },
    });
    expect(options.statusCode, options.body).toBe(201);
    expect(f.beginReplacementWebAuthnEnrollment).toHaveBeenCalledWith(
      sessionToken,
      replacedCredentialId,
      'control.openpc.example',
      origin,
    );
    expect(f.verifyCsrf).toHaveBeenCalledWith(
      sessionToken,
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      internalHeaders.origin,
      internalHeaders.host,
      'csrf-token',
    );
    const complete = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/complete',
      headers: internalHeaders,
      payload: { enrollmentId: replacementEnrollmentId, response: { id: 'replacement' } },
    });
    expect(complete.statusCode, complete.body).toBe(200);
    expect(f.registration.verify).toHaveBeenCalledWith(
      expect.objectContaining({ expectedOrigin: origin, expectedRpId: 'control.openpc.example' }),
    );
    await app.close();
  });

  it.each(['options', 'complete'])(
    'rejects an untrusted replacement browser origin at %s before touching enrollment',
    async (stage) => {
      const f = fixture();
      const app = buildIdentityService(
        f.kernel,
        undefined,
        undefined,
        undefined,
        () => null,
        f.registration,
      );
      const result = await app.inject({
        method: 'POST',
        url: `/v1/identity/webauthn/replacement/${stage}`,
        headers,
        payload:
          stage === 'options'
            ? { replacedCredentialId }
            : { enrollmentId: replacementEnrollmentId, response: { id: 'replacement' } },
      });
      expect(result.statusCode).toBe(401);
      expect(f.beginReplacementWebAuthnEnrollment).not.toHaveBeenCalled();
      expect(f.replacementWebAuthnEnrollmentContext).not.toHaveBeenCalled();
      expect(f.registration.verify).not.toHaveBeenCalled();
      await app.close();
    },
  );

  it('prepares and stages replacement separately before the governed commit', async () => {
    const f = fixture();
    const authorization = {
      propose: vi.fn(async () => ({
        participantId,
        privacyDomainId,
        principalId,
        sessionId,
        sessionEpoch: '1',
        participantEpoch: '5',
        principalEpoch: '7',
        assignmentId: '018f0000-0000-7000-8000-000000000131',
        assignmentRowVersion: '1',
        authorityEnvelopeId: '018f0000-0000-7000-8000-000000000132',
        authorityEpoch: '1',
        delegationEpoch: '0',
      })),
      authorize: vi.fn(async () => ({
        allowed: true,
        checkerPrincipalId: '018f0000-0000-7000-8000-000000000133',
        evidenceKind: 'USER_WEBAUTHN' as const,
        signerCredentialId: '018f0000-0000-7000-8000-000000000134',
        privacyDomainId,
        evidenceCbor: Buffer.from('evidence'),
        evidenceDigest: Buffer.alloc(32, 5),
        coseSign1: Buffer.from('signature'),
      })),
    };
    const candidateStager = { stage: vi.fn(async () => replacedCredentialId) };
    const app = buildIdentityService(
      f.kernel,
      undefined,
      undefined,
      authorization,
      undefined,
      f.registration,
      undefined,
      candidateStager,
    );
    const options = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/options',
      headers,
      payload: { replacedCredentialId },
    });
    expect(options.statusCode, options.body).toBe(201);

    const payload = { enrollmentId: replacementEnrollmentId, response: { id: 'replacement' } };
    const prepared = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/complete',
      headers,
      payload,
    });
    expect(prepared.statusCode, prepared.body).toBe(200);
    expect(prepared.json()).toMatchObject({
      replacedCredentialId,
      expectedRevision: '4',
      state: 'PREPARED',
    });
    const mutationHeaders = {
      ...headers,
      'idempotency-key': 'webauthn-replacement-0001',
      'x-openpc-aggregate-version': '4',
      'openpc-action-intent-digest': actionIntentDigest,
    };
    const staged = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/complete',
      headers: mutationHeaders,
      payload,
    });
    expect(staged.statusCode, staged.body).toBe(202);
    expect(staged.json()).toMatchObject({ state: 'APPROVAL_REQUIRED' });
    expect(candidateStager.stage).toHaveBeenCalledWith(
      expect.objectContaining({
        catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
        resourceId: replacedCredentialId,
        resourceType: 'participant',
      }),
      { sessionToken },
    );

    const committed = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/replacement/complete',
      headers: {
        ...mutationHeaders,
        'x-openpc-approval-request-id': '018f0000-0000-7000-8000-000000000135',
      },
      payload,
    });
    expect(committed.statusCode, committed.body).toBe(201);
    expect(f.completeReplacementWebAuthnEnrollment).toHaveBeenCalledWith(
      expect.objectContaining({
        mutationAuthorization: expect.objectContaining({
          checkerPrincipalId: '018f0000-0000-7000-8000-000000000133',
        }),
      }),
      replacementEnrollmentId,
      replacedCredentialId,
      expect.objectContaining({ externalCredentialId: 'registered-credential' }),
    );
    await app.close();
  });

  it('rejects cross-origin registration before creating durable state', async () => {
    const f = fixture();
    const app = buildIdentityService(
      f.kernel,
      undefined,
      undefined,
      undefined,
      undefined,
      f.registration,
    );
    const response = await app.inject({
      method: 'POST',
      url: '/v1/identity/webauthn/initial-registration/options',
      headers: { ...headers, origin: 'https://evil.example' },
      payload: {},
    });
    expect(response.statusCode).toBe(401);
    expect(f.sessionSnapshot).not.toHaveBeenCalled();
    expect(f.beginInitialWebAuthnEnrollment).not.toHaveBeenCalled();
    await app.close();
  });
});
