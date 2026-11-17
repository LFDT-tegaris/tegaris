import { localQaExecutionTimeoutMs } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import type { ConfigurationAuthorizer } from './authorization.js';
import {
  decodeLocalConfigurationProposal,
  decodeLocalMutationAuthorization,
  decodeLocalPolicyAuthorization,
} from './local-authorization-contract.js';
import { ConfigurationRepositoryError, type MutationAuthorization } from './persistence/types.js';

// Governed mutations perform tenant-scoped authority, approval, WebAuthn, and
// evidence checks in one request. Keep this above the normal 5 s HTTP budget so
// bounded local runtimes do not abort a valid authorization while PostgreSQL is
// under integration-test load.
const AUTHORIZATION_TIMEOUT_MS = 15_000;

export function createLocalConfigurationAuthorizer(
  identityUrl: string,
  internalToken: string,
  defaultPrivacyDomainId: string,
): ConfigurationAuthorizer {
  const request = async (path: string, body: unknown) => {
    const response = await fetch(new URL(path, identityUrl), {
      method: 'POST',
      headers: { 'authorization': `Bearer ${internalToken}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(localQaExecutionTimeoutMs(AUTHORIZATION_TIMEOUT_MS)),
    });
    if (!response.ok) {
      throw new ConfigurationRepositoryError(
        'PC-AUTH-0005',
        undefined,
        `identity-authorization:${path}`,
      );
    }
    return response.json();
  };
  return {
    async propose(input) {
      const privacyDomainId = input.privacyDomainId ?? defaultPrivacyDomainId;
      return {
        ...decodeLocalConfigurationProposal(
          await request('/internal/v1/local/policy/authorize', {
            sessionToken: input.sessionToken,
            privacyDomainId,
            actionIntentId: input.actionIntentId,
            resourceId: input.resourceId,
            stepUpRequired: false,
            csrfToken: input.csrfToken,
            origin: input.origin,
            host: input.host,
          }),
        ),
        privacyDomainId,
      };
    },
    async authorize(input): Promise<MutationAuthorization> {
      const privacyDomainId = input.privacyDomainId ?? defaultPrivacyDomainId;
      if (input.actionIntentDigest !== undefined && input.expectedRevision !== undefined) {
        return decodeLocalMutationAuthorization(
          await request('/internal/v1/local/configuration/authorize', {
            ...(input.idempotencyKey === undefined ? {} : { idempotencyKey: input.idempotencyKey }),
            ...(input.catalogOperationId === undefined
              ? {}
              : { catalogOperationId: input.catalogOperationId }),
            sessionToken: input.sessionToken,
            privacyDomainId,
            actionIntentId: input.actionIntentId,
            actionIntentDigest: input.actionIntentDigest,
            resourceId: input.resourceId,
            candidateDigest: input.candidateDigest,
            expectedRevision: input.expectedRevision,
            csrfToken: input.csrfToken,
            origin: input.origin,
            host: input.host,
          }),
        );
      }
      return decodeLocalPolicyAuthorization(
        await request('/internal/v1/local/policy/authorize', {
          sessionToken: input.sessionToken,
          privacyDomainId,
          actionIntentId: input.actionIntentId,
          resourceId: input.resourceId,
          stepUpRequired: false,
        }),
        privacyDomainId,
      );
    },
  };
}
