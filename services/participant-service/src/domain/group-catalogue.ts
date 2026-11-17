import type { PoolClient } from 'pg';
import { authorityReadPaths } from '../../../identity-service/src/db/authority-read-paths.js';
import { ParticipantKernelError } from './participant-errors.js';

export interface GroupCatalogueQuery {
  readonly search: string;
  readonly state: 'ALL' | 'ACTIVE' | 'RETIRED';
  readonly after?: string;
}

export interface GroupCatalogueCandidates {
  readonly ids: readonly string[];
  readonly observedAt: string;
}

/** Internal discovery only. The transport still reads every selected group through its owner. */
export async function groupCatalogueCandidates(
  client: PoolClient,
  participantId: string,
  principalId: string,
  privacyDomainId: string,
  query: GroupCatalogueQuery,
): Promise<GroupCatalogueCandidates> {
  const result = await client.query<{ id: string; observed_at: Date }>(
    `select authority_group_id::text id,statement_timestamp() observed_at
       from control.authority_group where participant_id=$1
         and ($2='ALL' or state::text=$2)
         and strpos(lower(group_name),lower($3))>0
         and ($4::uuid is null or authority_group_id>$4::uuid)
       order by authority_group_id limit 16385`,
    [participantId, query.state, query.search, query.after ?? null],
  );
  if (result.rows.length > 16_384) throw new ParticipantKernelError('PC-IDENTITY-1004');
  const observedAt = result.rows[0]?.observed_at.toISOString() ?? new Date().toISOString();
  if (result.rows.length === 0) return { ids: [], observedAt };
  const paths = await authorityReadPaths(
    client,
    participantId,
    principalId,
    privacyDomainId,
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    result.rows.map((row) => row.id),
    'LOW',
  );
  const counts = new Map<string, number>();
  for (const path of paths.rows)
    counts.set(path.resource_id, (counts.get(path.resource_id) ?? 0) + 1);
  if ([...counts.values()].some((count) => count > 1))
    throw new ParticipantKernelError('PC-IDENTITY-1002');
  return {
    ids: result.rows.filter((row) => counts.get(row.id) === 1).map((row) => row.id),
    observedAt,
  };
}
