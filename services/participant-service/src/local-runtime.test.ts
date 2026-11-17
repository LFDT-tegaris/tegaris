import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { EffectiveAuthority } from './domain/participant-kernel.js';
import {
  createLocalParticipantIdentityAdapters,
  readLocalParticipantRuntimeConfig,
} from './local-runtime.js';

const ids = {
  session: '018f0000-0000-7000-8000-000000000100',
  participant: '018f0000-0000-7000-8000-000000000101',
  principal: '018f0000-0000-7000-8000-000000000111',
  checker: '018f0000-0000-7000-8000-000000000112',
  envelope: '018f0000-0000-7000-8000-000000000121',
  assignment: '018f0000-0000-7000-8000-000000000122',
  privacy: '018f0000-0000-7000-8000-000000000201',
  approval: '018f0000-0000-7000-8000-000000000301',
  credential: '018f0000-0000-7000-8000-000000000401',
  resource: '018f0000-0000-7000-8000-000000000501',
} as const;
const sessionToken = `${ids.participant}.${ids.session}`;
const roots: string[] = [];

const context = {
  sessionId: ids.session,
  sessionEpoch: '6',
  participantId: ids.participant,
  principalId: ids.principal,
  participantEpoch: '1',
  principalEpoch: '2',
  assignmentId: ids.assignment,
  assignmentRowVersion: '3',
  authorityEnvelopeId: ids.envelope,
  authorityEpoch: '4',
  delegationEpoch: '5',
} as const;

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('local participant runtime', () => {
  it.each([
    { profile: undefined, delay: 6_000, authorized: true, expected: false, budget: 5_000 },
    { profile: 'LOCAL_QA_10X', delay: 6_000, authorized: true, expected: true, budget: 50_000 },
    { profile: 'LOCAL_QA_10X', delay: 6_000, authorized: false, expected: false, budget: 50_000 },
    { profile: 'LOCAL_QA_10X', delay: 51_000, authorized: true, expected: false, budget: 50_000 },
  ])(
    'keeps bounded Identity execution separate from authority: $profile/$delay/$authorized',
    async ({ profile, delay, authorized, expected, budget }) => {
      vi.stubEnv('OPENPC_LOCAL_RUNTIME', '1');
      vi.stubEnv('OPENPC_LOCAL_RUNTIME_QA_FIXTURE', '1');
      vi.stubEnv('OPENPC_LOCAL_QA_DURATION_PROFILE', profile);
      vi.useFakeTimers();
      const timeout = vi.spyOn(AbortSignal, 'timeout').mockImplementation((milliseconds) => {
        const controller = new AbortController();
        setTimeout(
          () => controller.abort(new DOMException('Owner execution timed out', 'TimeoutError')),
          milliseconds,
        );
        return controller.signal;
      });
      const adapters = createLocalParticipantIdentityAdapters(
        {
          PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
          PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
          identityInternalToken: 't'.repeat(32),
        },
        async (_input, init) =>
          new Promise<Response>((resolve, reject) => {
            const timer = setTimeout(
              () =>
                resolve(
                  response({
                    ...context,
                    role: 'operator',
                    contextMode: 'PLATFORM',
                    platformBootstrapEligible: authorized,
                    stepUpVerifiedAt: null,
                  }),
                ),
              delay,
            );
            init?.signal?.addEventListener(
              'abort',
              () => {
                clearTimeout(timer);
                reject(init.signal?.reason);
              },
              { once: true },
            );
          }),
      );
      const authentication = adapters.authentication.authenticate(`Bearer ${sessionToken}`);
      await vi.advanceTimersByTimeAsync(delay);
      const actor = await authentication;
      expect(timeout).toHaveBeenCalledExactlyOnceWith(budget);
      if (expected)
        expect(actor).toMatchObject({
          principalId: ids.principal,
          sessionId: ids.session,
          platform: true,
        });
      else expect(actor).toBeUndefined();
    },
  );

  it('rejects an unguarded duration profile without calling Identity', async () => {
    vi.stubEnv('OPENPC_LOCAL_RUNTIME', '1');
    vi.stubEnv('OPENPC_LOCAL_RUNTIME_QA_FIXTURE', '0');
    vi.stubEnv('OPENPC_LOCAL_QA_DURATION_PROFILE', 'LOCAL_QA_10X');
    const fetcher = vi.fn<typeof fetch>();
    const adapters = createLocalParticipantIdentityAdapters(
      {
        PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
        PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
        identityInternalToken: 't'.repeat(32),
      },
      fetcher,
    );
    await expect(
      adapters.authentication.authenticate(`Bearer ${sessionToken}`),
    ).resolves.toBeUndefined();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('accepts only the exact local-only configuration', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openpc-participant-runtime-'));
    roots.push(root);
    const databasePassword = join(root, 'database');
    const identityToken = join(root, 'identity');
    await Promise.all([
      writeFile(databasePassword, 'd'.repeat(32)),
      writeFile(identityToken, 'i'.repeat(32)),
    ]);
    const environment = {
      OPENPC_LOCAL_RUNTIME: '1',
      PARTICIPANT_DATABASE_HOST: '127.0.0.1',
      PARTICIPANT_DATABASE_PORT: '5432',
      PARTICIPANT_DATABASE_NAME: 'openpc_control',
      PARTICIPANT_DATABASE_USER: 'openpc_participant_runtime',
      PARTICIPANT_DATABASE_PASSWORD_FILE: databasePassword,
      PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
      PARTICIPANT_IDENTITY_INTERNAL_TOKEN_FILE: identityToken,
      PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
      PARTICIPANT_LISTEN: '0.0.0.0:3005',
    };
    await expect(readLocalParticipantRuntimeConfig(environment)).resolves.toMatchObject({
      databasePassword: 'd'.repeat(32),
      identityInternalToken: 'i'.repeat(32),
    });
    await expect(
      readLocalParticipantRuntimeConfig({ ...environment, PARTICIPANT_UNKNOWN: 'forbidden' }),
    ).rejects.toThrow('unknown local participant variable');
    await expect(
      readLocalParticipantRuntimeConfig({ ...environment, PARTICIPANT_LISTEN: '0.0.0.0:99999' }),
    ).rejects.toThrow();
  });

  it.each([ids.privacy, '018f0000-0000-7000-8000-000000007201'])(
    'binds authentication, policy signals, and mutation proof to the selected privacy %s',
    async (privacy) => {
      let proofPrivacy = privacy;
      const calls: Array<{ readonly path: string; readonly body: unknown }> = [];
      const fetcher: typeof fetch = async (input, init) => {
        const path = new URL(String(input)).pathname;
        const body = JSON.parse(String(init?.body)) as unknown;
        calls.push({ path, body });
        if (path.endsWith('/session/validate')) {
          return response({
            ...context,
            role: 'operator',
            contextMode: 'PARTICIPANT',
            privacyDomainId: privacy,
            contextEpoch: '5',
            stepUpVerifiedAt: null,
          });
        }
        if (path.endsWith('/policy/authorize')) return response(context);
        const { assignmentRowVersion, ...mutationContext } = context;
        return response({
          ...mutationContext,
          privacyDomainId: proofPrivacy,
          checkerPrincipalId: ids.checker,
          signerCredentialId: ids.credential,
          approvalRequestId: ids.approval,
          assignmentEpoch: assignmentRowVersion,
          evidenceKind: 'USER_WEBAUTHN',
          evidenceCbor: Buffer.from('evidence').toString('base64'),
          evidenceDigest: Buffer.alloc(32, 7).toString('base64'),
          coseSign1: Buffer.from('signature').toString('base64'),
        });
      };
      const adapters = createLocalParticipantIdentityAdapters(
        {
          PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
          PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
          identityInternalToken: 't'.repeat(32),
        },
        fetcher,
      );
      const actor = await adapters.authentication.authenticate(`Bearer ${sessionToken}`);
      expect(actor).toEqual({
        principalId: ids.principal,
        participantId: ids.participant,
        privacyDomainId: privacy,
        boundParticipantEpoch: '1',
        boundPrincipalEpoch: '2',
        boundEnvelopeEpoch: '4',
        sessionId: ids.session,
        sessionToken,
        platform: false,
      });

      const permission = {
        participantId: ids.participant,
        privacyDomainIds: [privacy],
        actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
        resourceIds: ['*'],
        riskClasses: ['HIGH'],
        validFrom: new Date(Date.now() - 60_000),
        validUntil: new Date(Date.now() + 60_000),
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 1,
      };
      const effective = {
        participantEpoch: '1',
        principalEpoch: '2',
        envelopeEpoch: '4',
        currentParticipantEpoch: '1',
        currentPrincipalEpoch: '2',
        currentEnvelopeEpoch: '4',
        envelope: {
          ...permission,
          id: ids.envelope,
          authorityEpoch: '4',
          state: 'ACTIVE',
          semanticDigest: `sha256:${'1'.repeat(64)}`,
        },
        assignment: {
          ...permission,
          id: ids.assignment,
          principalId: ids.principal,
          authorityEnvelopeId: ids.envelope,
          state: 'ACTIVE',
          delegationEpoch: '5',
          scopeDigest: `sha256:${'2'.repeat(64)}`,
        },
        delegations: [],
      } satisfies EffectiveAuthority;
      await expect(
        adapters.signals.resolve({
          actor: actor!,
          target: {
            privacyDomainId: privacy,
            actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            resourceId: ids.resource,
            riskClass: 'HIGH',
          },
          effective,
        }),
      ).resolves.toMatchObject({ platformPermits: true, stepUpFresh: true });
      await expect(
        adapters.mutationAuthorization.propose({
          actor: actor!,
          catalogOperationId: 'ID-OP-ENVELOPE-CREATE',
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          aggregateId: ids.resource,
          csrfToken: 'c'.repeat(32),
          origin: 'https://control.openpc.example',
          host: 'control.openpc.example',
        }),
      ).resolves.toMatchObject({
        participantId: ids.participant,
        privacyDomainId: privacy,
        principalId: ids.principal,
      });
      const mutationInput = {
        actor: actor!,
        catalogOperationId: 'ID-OP-ASSIGNMENT-REVOKE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        aggregateId: ids.resource,
        candidateDigest: `sha256:${'3'.repeat(64)}`,
        actionIntentDigest: `sha256:${'4'.repeat(64)}`,
        approvalRequestId: ids.approval,
        aggregateVersion: '6',
        csrfToken: 'c'.repeat(32),
        origin: 'https://control.openpc.example',
        host: 'control.openpc.example',
      } as const;
      await expect(adapters.mutationAuthorization.authorize(mutationInput)).resolves.toMatchObject({
        privacyDomainId: privacy,
        approvalRequestId: ids.approval,
        checkerPrincipalId: ids.checker,
      });
      expect(calls.map((call) => call.path)).toEqual([
        '/internal/v1/local/session/validate',
        '/internal/v1/local/policy/authorize',
        '/internal/v1/local/policy/authorize',
        '/internal/v1/local/configuration/authorize',
      ]);
      expect(calls[2]?.body).toMatchObject({
        sessionToken,
        privacyDomainId: privacy,
        csrfToken: 'c'.repeat(32),
        origin: 'https://control.openpc.example',
        host: 'control.openpc.example',
      });
      expect(calls[3]?.body).toMatchObject({
        sessionToken,
        privacyDomainId: privacy,
        catalogOperationId: 'ID-OP-ASSIGNMENT-REVOKE',
        candidateDigest: `sha256:${'3'.repeat(64)}`,
        actionIntentDigest: `sha256:${'4'.repeat(64)}`,
        expectedRevision: '6',
        csrfToken: 'c'.repeat(32),
        origin: 'https://control.openpc.example',
        host: 'control.openpc.example',
      });
      await adapters.signals.resolve({
        actor: actor!,
        target: {
          privacyDomainId: privacy,
          actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          resourceId: ids.resource,
          riskClass: 'LOW',
        },
        effective: {
          ...effective,
          envelope: { ...effective.envelope, stepUpRequired: false },
          assignment: { ...effective.assignment, stepUpRequired: false },
          delegations: [
            {
              ...effective.assignment,
              id: ids.resource,
              parentId: ids.assignment,
              grantorId: ids.principal,
              granteeId: ids.checker,
              stepUpRequired: true,
            },
          ],
        },
      });
      expect(calls.at(-1)?.body).toMatchObject({ stepUpRequired: true });
      proofPrivacy = privacy === ids.privacy ? '018f0000-0000-7000-8000-000000007201' : ids.privacy;
      await expect(
        adapters.mutationAuthorization.authorize(mutationInput),
      ).resolves.toBeUndefined();
    },
  );

  it('fails closed on malformed or unavailable identity responses', async () => {
    const adapters = createLocalParticipantIdentityAdapters(
      {
        PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
        PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
        identityInternalToken: 't'.repeat(32),
      },
      async () => response({ ...context, participantId: ids.resource, role: 'operator' }),
    );
    await expect(adapters.authentication.authenticate(`Bearer ${sessionToken}`)).resolves.toBe(
      undefined,
    );
    await expect(adapters.authentication.authenticate('Basic forbidden')).resolves.toBe(undefined);
  });

  it.each(['PLATFORM', undefined])(
    'does not derive Platform authority from an operator label in %s context',
    async (contextMode) => {
      const adapters = createLocalParticipantIdentityAdapters(
        {
          PARTICIPANT_IDENTITY_URL: 'http://identity-service:3001',
          PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: ids.privacy,
          identityInternalToken: 't'.repeat(32),
        },
        async () =>
          response({
            ...context,
            role: 'operator',
            contextMode,
            privacyDomainId: ids.privacy,
            stepUpVerifiedAt: null,
          }),
      );
      await expect(
        adapters.authentication.authenticate(`Bearer ${sessionToken}`),
      ).resolves.toBeUndefined();
    },
  );
});
