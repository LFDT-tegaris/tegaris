import type { PoolClient } from 'pg';
import { AuthorityFenceError } from './authority-fence.js';

export interface EnvelopePlatformContext {
  readonly platformContextId: string;
  readonly platformAuthorityEpoch: string;
}

/** The caller holds the current envelope path's Participant fence.
 * Null preserves legacy compatibility without granting Platform authority. */
export async function fenceEnvelopePlatformContext(
  client: PoolClient,
  participantId: string,
  envelopeId: string,
): Promise<EnvelopePlatformContext | null> {
  const selected = await client.query<{ platform_context_id: string | null }>(
    `select platform_context_id from control.authority_envelope
     where participant_id=$1 and authority_envelope_id=$2`,
    [participantId, envelopeId],
  );
  if (selected.rowCount !== 1) throw new AuthorityFenceError();
  if (selected.rows[0]!.platform_context_id === null) return null;
  const current = await client.query<{
    platform_context_id: string;
    platform_authority_epoch: string;
  }>('select * from openpc.lock_authority_envelope_platform_context($1)', [envelopeId]);
  if (current.rowCount !== 1) throw new AuthorityFenceError();
  return {
    platformContextId: current.rows[0]!.platform_context_id,
    platformAuthorityEpoch: current.rows[0]!.platform_authority_epoch,
  };
}
