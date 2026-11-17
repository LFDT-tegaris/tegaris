import type { Pool, PoolClient } from 'pg';
import {
  businessProviderObservationSchema,
  validateBusinessProviderObservation,
  type BusinessProviderRequest,
  type BusinessSigningProvider,
} from '../domain/business-signing-provider.js';
import { SigningRotationError } from '../domain/signing-rotation.js';
import { rotationDigest, type SigningRotationPartition } from './signing-rotation-store.js';
import { rotationAttempts } from './signing-rotation-attempts.js';
import { runScopedTransaction } from './scoped-transaction.js';

export async function observeSigningAttestation(
  pool: Pool,
  provider: BusinessSigningProvider,
  workloadCredentialId: string,
  scope: SigningRotationPartition & { readonly actionIntentId: string },
  request: BusinessProviderRequest,
  authorize: (client: PoolClient) => Promise<void>,
): Promise<boolean> {
  if (
    request.method !== 'SIGN_RECEIPT' ||
    request.callerWorkloadCredentialId !== workloadCredentialId
  )
    throw new SigningRotationError('DENIED');
  const transaction = <T>(
    scope: SigningRotationPartition & { readonly actionIntentId: string },
    operation: (client: PoolClient) => Promise<T>,
    operationId: string,
  ) => runScopedTransaction(pool, scope, () => operationId, operation);
  const claimed = await transaction(
    scope,
    async (client) => {
      await authorize(client);
      const attempts = await rotationAttempts(client, scope, request.operationId);
      const retained = attempts.find((a) => a.attemptId === request.attemptId);
      if (!retained || !rotationDigest(retained.request).equals(rotationDigest(request)))
        throw new SigningRotationError('CONFLICT');
      if (retained.observation !== null) {
        if (retained.observation.outcome === 'SUCCEEDED') return 'OBSERVED' as const;
        if (retained.state === 'OBSERVED')
          await client.query(
            `update control.signing_provider_attempt set state='REJECTED' where attempt_id=$1 and state='OBSERVED'`,
            [request.attemptId],
          );
        return 'REJECTED' as const;
      }
      const updated = await client.query(
        `update control.signing_provider_attempt set state='DISPATCHING' where participant_id=$1 and privacy_domain_id=$2
        and attempt_id=$3 and operation_id=$4 and state='READY' and request->>'method'='SIGN_RECEIPT'`,
        [scope.participantId, scope.privacyDomainId, request.attemptId, request.operationId],
      );
      return updated.rowCount === 1 ? ('DISPATCH' as const) : ('LOOKUP' as const);
    },
    request.operationId,
  );
  if (claimed === 'OBSERVED') return true;
  if (claimed === 'REJECTED') return false;
  let observation;
  try {
    const result =
      claimed === 'DISPATCH'
        ? await provider.perform(request)
        : await provider.lookup(request.attemptId);
    if (result === undefined) return false;
    observation = businessProviderObservationSchema.parse(result);
    validateBusinessProviderObservation(request, observation);
  } catch {
    return false;
  }
  await transaction(
    scope,
    async (client) => {
      const updated = await client.query(
        `update control.signing_provider_attempt set observation=$4,observation_digest=$5,state='OBSERVED'
        where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state='DISPATCHING'`,
        [
          scope.participantId,
          scope.privacyDomainId,
          request.attemptId,
          observation,
          rotationDigest(observation),
        ],
      );
      if (updated.rowCount !== 1) {
        const retained = (await rotationAttempts(client, scope, request.operationId)).find(
          (a) => a.attemptId === request.attemptId,
        );
        if (
          !retained?.observation ||
          !rotationDigest(retained.observation).equals(rotationDigest(observation))
        )
          throw new SigningRotationError('AMBIGUOUS');
      }
      if (observation.outcome === 'REJECTED')
        await client.query(
          `update control.signing_provider_attempt set state='REJECTED' where attempt_id=$1 and state='OBSERVED'`,
          [request.attemptId],
        );
    },
    request.operationId,
  );
  return observation.outcome === 'SUCCEEDED';
}
