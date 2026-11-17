import { sign, type KeyObject } from 'node:crypto';
import { z } from 'zod';
import { expect } from 'vitest';
import { sha } from './public-governance-client.js';
import type { oidcProviderFixture } from './oidc-provider-fixture.js';
import type { PlatformRecoveryCommand } from '../../../services/identity-service/src/db/platform-recovery-command.js';

export interface RootRecoveryActor {
  principalId: string;
  sessionToken: string;
  sessionId: string;
  credentialId?: string;
  externalCredentialId?: string;
  privateKey?: KeyObject;
  counter: number;
}
const object = z.record(z.string(), z.unknown());
const challengeSchema = z.object({
  challengeId: z.uuidv7(),
  challenge: z.string(),
  intentDigest: z.string(),
  rpId: z.string(),
  credentialIds: z.array(z.string()),
});

/** External IdP/authenticator inputs only. Sessions, challenges, counters and
 * recovery effects are created and checked by their real HTTP/database owners. */
export function rootExpiryRecoveryClient(
  origin: string,
  participantId: string,
  privacyDomainId: string,
) {
  let requestSequence = 0;
  const observe = async <T>(
    endpoint: string,
    run: (headers: (status: number) => void) => Promise<T>,
    command?: PlatformRecoveryCommand,
  ): Promise<T> => {
    const sequence = ++requestSequence;
    const started = performance.now();
    const emit = (stage: string, fields: Record<string, string | number> = {}) =>
      process.stdout.write(
        JSON.stringify({
          boundary: 'finite_root_recovery_http',
          sequence,
          endpoint,
          ...(command ? { command: command.kind } : {}),
          ...(command && 'phase' in command ? { phase: command.phase } : {}),
          stage,
          at: new Date().toISOString(),
          elapsedMs: Math.round(performance.now() - started),
          ...fields,
        }) + '\n',
      );
    emit('START');
    try {
      const value = await run((status) => emit('HEADERS', { status }));
      emit('COMPLETE');
      return value;
    } catch (error) {
      emit('FAILED', { errorName: error instanceof Error ? error.name : 'UnknownError' });
      throw error;
    }
  };
  const request = async (
    path: string,
    body: unknown,
    actor?: RootRecoveryActor,
    extra: Record<string, string> = {},
    command?: PlatformRecoveryCommand,
  ) =>
    observe(
      path === '/api/v1/session/csrf'
        ? 'CSRF'
        : path === '/v1/identity/oidc/begin'
          ? 'OIDC_BEGIN'
          : path === '/v1/identity/oidc/callback'
            ? 'OIDC_CALLBACK'
            : 'RECOVERY_COMMAND',
      async (headers) => {
        const response = await fetch(`${origin}${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'Origin': origin,
            ...(actor ? { Cookie: `__Host-openpc_session=${actor.sessionToken}` } : {}),
            ...extra,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(15000),
        });
        headers(response.status);
        return {
          status: response.status,
          body: object.parse(await response.json()),
          cookie: response.headers.get('set-cookie'),
        };
      },
      command,
    );
  const csrf = async (actor: RootRecoveryActor) => {
    const response = await request(
      '/api/v1/session/csrf',
      { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
      actor,
    );
    expect(response.status).toBe(200);
    return z.string().parse(response.body.csrfToken);
  };
  const command = async (
    actor: RootRecoveryActor,
    enrollmentId: string,
    command: PlatformRecoveryCommand,
    privacy = privacyDomainId,
  ) =>
    request(
      `/v1/identity/platform-recovery/enrollments/${enrollmentId}/commands`,
      { privacyDomainId: privacy, command },
      actor,
      { 'X-CSRF-Token': await csrf(actor) },
      command,
    );
  return {
    command,
    async login(
      provider: Awaited<ReturnType<typeof oidcProviderFixture>>,
      principalId: string,
    ): Promise<RootRecoveryActor> {
      // Account selection and the complete exchange are deliberately sequential.
      provider.setSubject(principalId);
      const started = await request('/v1/identity/oidc/begin', { participantId });
      expect(started.status).toBe(200);
      const start = z
        .object({
          transactionId: z.string(),
          clientId: z.string(),
          redirectUri: z.string(),
          state: z.string(),
          nonce: z.string(),
          codeChallenge: z.string(),
        })
        .parse(started.body);
      const authorization = new URL(`${provider.issuer}/authorize`);
      authorization.search = new URLSearchParams({
        response_type: 'code',
        client_id: start.clientId,
        redirect_uri: start.redirectUri,
        state: start.state,
        nonce: start.nonce,
        code_challenge: start.codeChallenge,
        code_challenge_method: 'S256',
      }).toString();
      const redirect = await observe('OIDC_AUTHORIZE', async (headers) => {
        const response = await fetch(authorization, {
          redirect: 'manual',
          signal: AbortSignal.timeout(10000),
        });
        headers(response.status);
        return response;
      });
      expect(redirect.status).toBe(302);
      const location = new URL(z.string().parse(redirect.headers.get('location')));
      const completed = await request(
        '/v1/identity/oidc/callback',
        {
          transactionId: start.transactionId,
          state: location.searchParams.get('state'),
          authorizationCode: location.searchParams.get('code'),
        },
        undefined,
        { Cookie: z.string().parse(started.cookie).split(';')[0]! },
      );
      expect(completed.status).toBe(201);
      const cookie = z.string().parse(completed.cookie);
      const token = /__Host-openpc_session=([^;]+)/u.exec(cookie)?.[1];
      expect(token).toBeDefined();
      const session = await observe('SESSION', async (headers) => {
        const snapshot = await fetch(`${origin}/api/v1/session`, {
          headers: { Cookie: `__Host-openpc_session=${token}` },
          signal: AbortSignal.timeout(10000),
        });
        headers(snapshot.status);
        expect(snapshot.status).toBe(200);
        return z
          .object({
            principalId: z.literal(principalId),
            participantId: z.literal(participantId),
            contextMode: z.literal('PLATFORM'),
            sessionId: z.uuidv7(),
            state: z.literal('ACTIVE'),
          })
          .parse(await snapshot.json());
      });
      return { principalId, sessionToken: token!, sessionId: session.sessionId, counter: 1 };
    },
    async challenge(
      actor: RootRecoveryActor,
      enrollmentId: string,
      recoveryId: string,
      phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE',
    ) {
      const response = await command(actor, enrollmentId, { kind: 'CHALLENGE', recoveryId, phase });
      expect(response.status).toBe(200);
      return challengeSchema.parse(response.body);
    },
    proof(
      actor: RootRecoveryActor,
      recoveryId: string,
      phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE',
      challenge: z.infer<typeof challengeSchema>,
    ): PlatformRecoveryCommand {
      if (!actor.privateKey || !actor.externalCredentialId)
        throw new Error('Independent external authenticator material is required');
      expect(challenge.credentialIds).toEqual([actor.externalCredentialId]);
      const clientData = Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin,
          crossOrigin: false,
        }),
      );
      const authenticatorData = Buffer.alloc(37);
      sha(challenge.rpId).copy(authenticatorData);
      authenticatorData[32] = 5;
      authenticatorData.writeUInt32BE(++actor.counter, 33);
      const signature = sign(
        'sha256',
        Buffer.concat([authenticatorData, sha(clientData)]),
        actor.privateKey,
      );
      return {
        kind: 'PROVE',
        recoveryId,
        phase,
        proof: {
          challengeId: challenge.challengeId,
          challenge: challenge.challenge,
          intentDigest: challenge.intentDigest,
          assertion: JSON.stringify({
            credentialId: actor.externalCredentialId,
            clientDataJson: clientData.toString('base64url'),
            authenticatorData: authenticatorData.toString('base64url'),
            signature: signature.toString('base64url'),
          }),
        },
      };
    },
  };
}
