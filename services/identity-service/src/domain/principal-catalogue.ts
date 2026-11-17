import type { PoolClient } from 'pg';
import { authorityReadPaths } from '../db/authority-read-paths.js';
import { IdentityKernelError } from './identity-errors.js';
import type { PrincipalRecord } from './principal-lifecycle.js';

export interface PrincipalCatalogueQuery {
  readonly search: string;
  readonly state: PrincipalRecord['state'] | 'ALL';
  readonly kind: PrincipalRecord['kind'] | 'ALL';
  readonly after?: string;
}

/** Internal candidate discovery. Public disclosure still requires each principal's live read fence. */
export async function principalCatalogueCandidates(
  client: PoolClient,
  participantId: string,
  principalId: string,
  privacyDomainId: string,
  query: PrincipalCatalogueQuery,
) {
  const result = await client.query<{ id: string; observed_at: Date }>(
    `select principal_id::text id,statement_timestamp() observed_at from control.principal
     where participant_id=$1 and state in ('PROVISIONED','ACTIVE','SUSPENDED','REVOKED','OFFBOARDED')
       and ($2='ALL' or state::text=$2) and ($3='ALL' or kind::text=$3)
       and strpos(lower(display_label),lower($4))>0
       and ($5::uuid is null or principal_id>$5::uuid)
     order by principal_id limit 16385`,
    [participantId, query.state, query.kind, query.search, query.after ?? null],
  );
  if (result.rows.length > 16_384) throw new IdentityKernelError('PC-IDENTITY-1004');
  const observedAt = result.rows[0]?.observed_at.toISOString() ?? new Date().toISOString();
  if (!result.rows.length) return { ids: [], observedAt };
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
    throw new IdentityKernelError('PC-IDENTITY-1002');
  return {
    ids: result.rows.filter((row) => counts.get(row.id) === 1).map((row) => row.id),
    observedAt,
  };
}
