import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import type { AuthorityFence, BoundAuthority } from './authority-fence.js';

import { authoritySnapshotColumns } from './authority-snapshot-columns.js';

export interface RetainedAuthoritySnapshot {
  readonly bytes: Buffer;
  readonly digest: Buffer;
}

export async function readAuthoritySnapshotRows(
  client: PoolClient,
  participantId: string,
  fence: AuthorityFence,
) {
  const dependencies: Record<string, readonly unknown[]> = {};
  for (const table of Object.keys(
    authoritySnapshotColumns,
  ).sort() as (keyof typeof authoritySnapshotColumns)[]) {
    const ids = [...new Set((fence[table] ?? []).map((row) => row.id))].sort();
    const columns = authoritySnapshotColumns[table];
    // SQL identifiers originate exclusively from this closed owning projection.
    const projection = columns.map((column) => `'${column}',${column}::text`).join(',');
    const selected = await client.query<{ row: Record<string, string | null> }>(
      `select jsonb_build_object(${projection}) as row from control.${table}
       where participant_id=$1 and ${columns[0]}=any($2::uuid[]) order by ${columns[0]}`,
      [participantId, ids],
    );
    if (selected.rowCount !== ids.length)
      throw new Error('Fenced authority snapshot is incomplete');
    dependencies[table] = selected.rows.map((row) => row.row);
  }
  return dependencies;
}

/** Read only the exact rows already held by the authority fence, while its transaction remains open. */
export async function captureAuthoritySnapshot(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  operationId: string,
  authorities: readonly BoundAuthority[],
  fence: AuthorityFence,
): Promise<RetainedAuthoritySnapshot> {
  const dependencies = await readAuthoritySnapshotRows(client, participantId, fence);
  const recorded = await client.query<{ nowNs: string }>(
    `select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"`,
  );
  if (recorded.rowCount !== 1 || recorded.rows[0] === undefined)
    throw new Error('Missing database snapshot time');
  const bytes = Buffer.from(
    canonicalDefinitionJson({
      schema: 'pc.control.precommit-authority-snapshot.v1',
      participantId,
      privacyDomainId,
      operationId,
      recordedAtNs: recorded.rows[0].nowNs,
      decision: 'ALLOW',
      authorities: authorities.map((authority) => ({
        principalId: authority.principalId,
        sessionId: authority.sessionId,
        sessionEpoch: authority.sessionEpoch,
        participantEpoch: authority.participantEpoch,
        principalEpoch: authority.principalEpoch,
        assignmentId: authority.assignmentId,
        assignmentRowVersion: authority.assignmentRowVersion,
        authorityEnvelopeId: authority.authorityEnvelopeId,
        authorityEpoch: authority.authorityEpoch,
        delegationEpoch: authority.delegationEpoch,
        privacyDomainId: authority.privacyDomainId,
        actionIntentId: authority.actionIntentId,
        resourceId: authority.resourceId,
      })),
      dependencies,
    }),
    'utf8',
  );
  if (bytes.length > 65536) throw new Error('Authority snapshot exceeds receipt custody bound');
  return { bytes, digest: createHash('sha256').update(bytes).digest() };
}
