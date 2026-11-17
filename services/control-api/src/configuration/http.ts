import type { ConfigurationBusinessEvidence } from './persistence/business-receipt-writer.js';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';

import type { ConfigurationAuthorizer } from './authorization.js';
import { registerResourceRoutes } from './resource-http.js';
import { registerEvidenceRoutes } from '../evidence/http.js';
import { registerNotificationEndpointRoutes } from '../notifications/endpoint-http.js';

export interface ConfigurationApiOptions {
  readonly notificationEndpointVerification?: import('../notifications/endpoint-verification-workflow.js').NotificationEndpointVerificationWorkflow;
  readonly notificationEndpointOwners?: import('../notifications/endpoint-owner-contract.js').NotificationEndpointOwners;
  readonly storeRetirementAdmissions?: ReadonlyMap<
    string,
    import('../evidence/store-retirement-admission.js').StoreRetirementAdmissionAuthority
  >;
  readonly factArtifacts?: import('./fact-artifacts.js').FactArtifactsClient;
  readonly moduleReleaseVerifier?: import('../../../module-registry/src/db/module-release-store.js').ModuleReleaseVerifier;
  readonly pool: Pool;
  readonly authorizer: ConfigurationAuthorizer;
  readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  readonly businessEvidence?: ConfigurationBusinessEvidence;
}

/** Public configuration owners, including the typed deployment publication extension. */
export function registerConfigurationRoutes(
  app: FastifyInstance,
  options: ConfigurationApiOptions,
): void {
  registerResourceRoutes(app, options);
  registerEvidenceRoutes(app, options);
  registerNotificationEndpointRoutes(app, options, options.notificationEndpointVerification);
}
