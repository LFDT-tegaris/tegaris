import type { PoolClient } from 'pg';
import { z } from 'zod';
/** Exact original phase owner, never caller-controlled predecessor selection.
 * Public trust stays REVOKED after private retirement. */
export async function revokeIdentityEnvelopeRecoveryTrust(
  client: PoolClient,
  expected: { predecessorSignerId: string; operationId: string },
) {
  const result = await client.query<{ revocation: unknown }>(
    'select openpc.revoke_identity_envelope_recovery_trust() as revocation',
  );
  if (result.rowCount !== 1) throw Error('Identity envelope predecessor revocation unavailable');
  return z
    .strictObject({
      signerId: z.literal(expected.predecessorSignerId),
      operationId: z.literal(expected.operationId),
      state: z.literal('REVOKED'),
    })
    .parse(result.rows[0]?.revocation);
}
