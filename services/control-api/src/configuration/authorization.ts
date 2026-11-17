import type { MutationAuthorization } from './persistence/types.js';

export type { MutationCandidateAuthority as ConfigurationProposalAuthorization } from '../../../identity-service/src/db/mutation-candidate-store.js';
import type { MutationCandidateAuthority as ConfigurationProposalAuthorization } from '../../../identity-service/src/db/mutation-candidate-store.js';

export interface ConfigurationAuthorizationInput {
  readonly sessionToken: string;
  readonly idempotencyKey?: string;
  readonly catalogOperationId?: string;
  readonly participantId: string;
  readonly privacyDomainId?: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest?: string;
  readonly resourceId: string;
  readonly candidateDigest: string;
  readonly expectedRevision?: string;
  readonly makerCheckerRequired: boolean;
  readonly stepUpRequired: boolean;
  readonly csrfToken?: string;
  readonly origin?: string;
  readonly host?: string;
}

/**
 * A thin port to the identity/policy authority owner.  This API never decides
 * roles, delegations, approvals, or MFA locally.
 */
export interface ConfigurationAuthorizer {
  propose?(input: ConfigurationAuthorizationInput): Promise<ConfigurationProposalAuthorization>;
  authorize(input: ConfigurationAuthorizationInput): Promise<MutationAuthorization>;
}
