import { afterAll, describe, expect, it } from 'vitest';

import {
  buildIdentityService,
  type OidcClientConfiguration,
} from '../../../services/identity-service/src/app.js';
import type { IdentityTrustAdapter } from '../../../services/identity-service/src/domain/trust-adapter.js';
import { buildParticipantService } from '../../../services/participant-service/src/app.js';

const oidcClient: OidcClientConfiguration = {
  issuer: 'https://issuer.openpc.example',
  clientId: 'openpc-control',
  redirectUri: 'https://control.openpc.example/callback',
};

const trustAdapter: IdentityTrustAdapter = {
  async exchangeAuthorizationCode() {
    throw new Error('the fail-closed kernel must not exchange an authorization code');
  },
  async verifyWebAuthnAssertion() {
    return undefined;
  },
};

const identityApp = buildIdentityService(undefined, trustAdapter, oidcClient);
const participantApp = buildParticipantService();

afterAll(async () => {
  await Promise.all([identityApp.close(), participantApp.close()]);
});

describe('identity and authority service trust boundaries', () => {
  it('rejects browser-supplied OIDC state, nonce, and PKCE material', async () => {
    const response = await identityApp.inject({
      method: 'POST',
      url: '/api/v1/session/oidc/authorization',
      payload: {
        codeVerifier:
          'OpenPC-C04-PKCE-verifier-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        nonce: 'caller-controlled-nonce',
        state: 'caller-controlled-state',
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: 'PC-AUTH-0002' } });
  });

  it('fails closed when a PostgreSQL identity repository is not wired', async () => {
    const response = await identityApp.inject({
      method: 'POST',
      url: '/api/v1/session/oidc/authorization',
      payload: {},
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'PC-IDENTITY-1004' } });
  });

  it('rejects caller-supplied authority graph, epochs, and authorization signals', async () => {
    const response = await participantApp.inject({
      method: 'POST',
      url: '/v1/authority/evaluate',
      payload: {
        privacyDomainId: 'privacy-a',
        actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
        resourceId: 'resource-a',
        riskClass: 'HIGH',
        currentAuthorityEpoch: '999',
        platformPermits: true,
        stepUpFresh: true,
      },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: { code: 'PC-IDENTITY-1004' } });
  });
});
