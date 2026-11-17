import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';

/** Participant's public trust persistence boundary, within the original scoped
 * publication transaction. The definer admits only its exact committed dual
 * proof/custody step; callers never receive ordinary key-governor privileges. */
export async function admitIdentityEnvelopeRecoveryTrust(
  client: PoolClient,
  trust: IdentityEnvelopeSigningTrust,
) {
  const digest = identityEnvelopeSigningTrustDigest(trust);
  const result = await client.query<{ admission: unknown }>(
    'select openpc.admit_identity_envelope_recovery_trust($1,$2) as admission',
    [identityEnvelopeSigningTrustPreimage(trust), Buffer.from(digest.slice(7), 'hex')],
  );
  const admission = z
    .strictObject({
      signerId: z.literal(trust.signerId),
      trustDigest: z.literal(digest),
      state: z.literal('ADMITTED'),
    })
    .parse(result.rows[0]?.admission);
  if (result.rowCount !== 1) throw new Error('Identity envelope trust admission unavailable');
  return admission;
}
