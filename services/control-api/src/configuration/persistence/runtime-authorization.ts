import type { PoolClient } from 'pg';
import {
  verifyRuntimeMutationAuthorization,
  RuntimeMutationAuthorizationError,
} from '../../../../identity-service/src/db/runtime-mutation-authorization.js';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { ConfigurationRepositoryError, type MutationContext } from './types.js';

/** Preserve the public configuration error contract around the shared identity verifier. */
export async function verifyConfigurationRuntimeAuthorization(
  client: PoolClient,
  context: MutationContext,
  candidateDigest: Buffer,
  verifier: IdentityRuntimeVerifier | undefined,
): Promise<void> {
  try {
    await verifyRuntimeMutationAuthorization(client, context, candidateDigest, verifier);
  } catch (error) {
    if (error instanceof RuntimeMutationAuthorizationError)
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    throw error;
  }
}
