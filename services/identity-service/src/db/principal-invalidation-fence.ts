import type { PoolClient } from 'pg';

import type { AuthorityFence } from './authority-fence.js';

/** Include dependent rows in the same lock order before suspending or recovering a principal. */
export async function principalInvalidationFence(
  client: PoolClient,
  participantId: string,
  principalId: string,
  revokeCredentials: boolean,
): Promise<AuthorityFence> {
  const sessions = await client.query<{ id: string }>(
    `select session_id::text as id from control.session where participant_id=$1 and principal_id=$2`,
    [participantId, principalId],
  );
  const credentials = revokeCredentials
    ? await client.query<{ id: string }>(
        `select credential_id::text as id from control.credential where participant_id=$1 and principal_id=$2`,
        [participantId, principalId],
      )
    : undefined;
  return {
    principal: [{ id: principalId, write: true }],
    session: sessions.rows.map(({ id }) => ({ id, write: true })),
    credential: credentials?.rows.map(({ id }) => ({ id, write: true })) ?? [],
  };
}
