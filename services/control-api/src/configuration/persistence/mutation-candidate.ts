import type { Pool, PoolClient } from 'pg';
import { AuthorityFenceError } from '../../../../identity-service/src/db/authority-fence.js';
import {
  MutationCandidateError,
  stageMutationCandidateInTransaction,
  type MutationCandidateContext,
} from '../../../../identity-service/src/db/mutation-candidate-store.js';
import { ConfigurationRepositoryError } from './types.js';
export type { MutationCandidateContext } from '../../../../identity-service/src/db/mutation-candidate-store.js';

function retryableCandidateRace(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error.code === '40001' || error.code === '40P01')
  );
}

async function begin(client: PoolClient, context: MutationCandidateContext): Promise<void> {
  // Exact authority rows remain locked through commit; the unique proposal key
  // serializes concurrent inserts without a transaction-wide stale snapshot.
  await client.query('begin isolation level read committed');
  await client.query('set local row_security=on');
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [
      context.participantId,
      context.privacyDomainId,
      context.authorization.sessionId,
      context.actionIntentId,
    ],
  );
}

/** Configuration transport adapter around the shared identity/control-store candidate owner. */
export async function stageMutationCandidate(
  pool: Pool,
  context: MutationCandidateContext,
): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const client = await pool.connect();
    try {
      await begin(client, context);
      const resourceId = await stageMutationCandidateInTransaction(client, context);
      await client.query('commit');
      return resourceId;
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      if (error instanceof AuthorityFenceError)
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      if (error instanceof MutationCandidateError)
        throw new ConfigurationRepositoryError(error.code);
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505')
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      if (!retryableCandidateRace(error)) throw error;
      if (attempt === 2) throw new ConfigurationRepositoryError('PC-DATA-6007');
    } finally {
      client.release();
    }
  }
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}
