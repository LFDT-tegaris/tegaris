import type { PoolClient } from 'pg';
import { z } from 'zod';
/** The original scoped transaction owns this exact public selection result.
 * This has no private-key or ordinary permission effect. */
export async function selectIdentityEnvelopeRecoveryTrust(
  client: PoolClient,
  expected: { signerId: string; trustDigest: string; selectionAdmissionVersion: string },
) {
  const selected = await client.query<{ selection: unknown }>(
    'select openpc.select_identity_envelope_recovery_trust() as selection',
  );
  if (selected.rowCount !== 1) throw Error('Identity envelope trust selection unavailable');
  return z
    .strictObject({
      signerId: z.literal(expected.signerId),
      trustDigest: z.literal(expected.trustDigest),
      selectionAdmissionVersion: z.literal(expected.selectionAdmissionVersion),
      state: z.literal('SELECTED'),
    })
    .parse(selected.rows[0]?.selection);
}
