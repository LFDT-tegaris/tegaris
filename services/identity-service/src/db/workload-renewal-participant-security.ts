import type { PoolClient } from 'pg';

export class WorkloadRenewalParticipantSecurityUnavailable extends Error {
  constructor() {
    super('Participant signing security history is unavailable');
  }
}
/** Existing Participant lifecycle owner authenticates actual invoker scope,
 * grants and complete tenant history before returning authoritative absence0.
 * C04 Participant/privacy fences must already be held by the caller. */
export async function readWorkloadRenewalParticipantSecurityEpoch(
  client: PoolClient,
  scope: { readonly participantId: string; readonly privacyDomainId: string },
): Promise<bigint> {
  const result = await client.query<{ epoch: string }>(
    'select openpc.workload_renewal_participant_security_epoch($1,$2)::text as epoch',
    [scope.participantId, scope.privacyDomainId],
  );
  const epoch = result.rows[0]?.epoch;
  if (
    result.rowCount !== 1 ||
    epoch === undefined ||
    !/^(0|[1-9][0-9]{0,19})$/u.test(epoch) ||
    BigInt(epoch) > 18446744073709551615n
  )
    throw new WorkloadRenewalParticipantSecurityUnavailable();
  return BigInt(epoch);
}
