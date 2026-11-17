import type { PoolClient } from 'pg';

/** Always precedes stream/object locks; shared by rule changes, admission and lifecycle work. */
export async function lockEvidenceLifecycle(
  client: PoolClient,
  participantId: string,
  _privacyDomainId: string,
) {
  await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
    `evidence-lifecycle:${participantId}`,
  ]);
}
