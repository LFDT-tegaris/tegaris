import type { PoolClient } from 'pg';
import { ConfigurationRepositoryError } from './persistence/types.js';

/** Resolve current workload credential ownership for a management command.
 * Runtime execution still requires actual mTLS and independent live authority. */
export async function resolveExecutionPrincipal(
  client: PoolClient,
  participantId: string,
  workloadId: string | undefined,
): Promise<string | undefined> {
  if (workloadId === undefined) return undefined;
  const result = await client.query<{ principalId: string }>(
    `select distinct principal.principal_id::text as "principalId"
     from control.principal principal join control.credential credential using(participant_id,principal_id)
     where principal.participant_id=$1 and principal.kind='WORKLOAD' and principal.state='ACTIVE'
      and credential.kind='WORKLOAD_MTLS' and credential.audience=$2 and credential.state='ACTIVE'
      and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp()`,
    [participantId, workloadId],
  );
  if (result.rowCount !== 1 || !result.rows[0])
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  return result.rows[0].principalId;
}
