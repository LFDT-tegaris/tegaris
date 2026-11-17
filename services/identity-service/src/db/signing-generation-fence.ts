import type { PoolClient } from 'pg';
import { z } from 'zod';
import type { AuthorityFence } from './authority-fence.js';
import { authoritySnapshotColumns } from './authority-snapshot-columns.js';
import { SigningRotationError } from '../domain/signing-rotation.js';

export async function signingGenerationHistoricalFence(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  generationId: string,
): Promise<AuthorityFence> {
  const selected = await client.query<{ dependencies: unknown }>(
    `select c.candidate_document->'context'->'originalAuthority'->'dependencies' as dependencies
     from control.signing_authorization_generation g join control.mutation_candidate c on c.mutation_candidate_id=g.candidate_id
     where g.participant_id=$1 and g.privacy_domain_id=$2 and g.generation_id=$3 and g.state='STAGED'`,
    [participantId, privacyDomainId, generationId],
  );
  if (selected.rowCount === 0) return {};
  if (selected.rowCount !== 1) throw new SigningRotationError('CONFLICT');
  const dependencies = z
    .record(z.string(), z.array(z.record(z.string(), z.string().nullable())))
    .parse(selected.rows[0]!.dependencies);
  return Object.fromEntries(
    Object.entries(authoritySnapshotColumns).map(([table, columns]) => [
      table,
      (dependencies[table] ?? []).map((row) => ({ id: z.uuidv7().parse(row[columns[0]]) })),
    ]),
  );
}
