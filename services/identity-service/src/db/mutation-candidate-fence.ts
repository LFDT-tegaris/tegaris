import type { PoolClient } from 'pg';

/** Business identity is stable across approval attempts. Lock after authority fences. */
export async function fenceMutationIntent(
  client: PoolClient,
  scope: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly principalId: string;
    readonly actionIntentId: string;
    readonly catalogOperationId: string;
    readonly idempotencyKey: string;
  },
): Promise<void> {
  await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
    JSON.stringify([
      'mutation-intent',
      scope.participantId,
      scope.privacyDomainId,
      scope.principalId,
      scope.actionIntentId,
      scope.catalogOperationId,
      scope.idempotencyKey,
    ]),
  ]);
}

/** Supersession never rewrites historical state, expiry, actor binding or proof. */
export function currentMutationCandidateSql(alias: string): string {
  if (!/^[a-z_]+$/u.test(alias)) throw new Error('Invalid candidate SQL alias');
  return `not exists (select 1 from control.mutation_candidate successor
    where successor.participant_id=${alias}.participant_id
      and successor.privacy_domain_id=${alias}.privacy_domain_id
      and successor.predecessor_candidate_id=${alias}.mutation_candidate_id)`;
}
