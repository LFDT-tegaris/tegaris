import type { PoolClient } from 'pg';

import { readWorkloadPolicyPrediction } from '../../../identity-service/src/domain/workload-policy-prediction.js';
import { ContractError } from '../domain/errors.js';

const CALL_CAPABILITY = 'CALL_RESULT_DISCLOSURE';

interface SimulationAuthorityRow {
  readonly assignmentId: string;
  readonly envelopeId: string;
  readonly principalId: string;
  readonly roleId: string;
  readonly workloadId: string;
}

interface SimulationAuthorityChoice extends SimulationAuthorityRow {
  readonly workloadDisplayLabel: string;
  readonly roleDisplayName: string;
}

export interface ResolvedSimulationAuthority extends SimulationAuthorityRow {
  readonly authorityDigest: string;
  readonly credentialValidUntilNs: string;
  readonly nextTransitionNs?: bigint;
}

export interface SimulationWorkload {
  readonly principalId: string;
  readonly workloadId: string;
}

const currentAuthority = `
  from control.credential credential
  join control.principal principal
    on principal.participant_id=credential.participant_id
   and principal.principal_id=credential.principal_id
  join control.assignment assignment
    on assignment.participant_id=principal.participant_id
   and assignment.principal_id=principal.principal_id
  join control.authority_role role
    on role.participant_id=assignment.participant_id
   and role.role_id=assignment.role_id
  join control.authority_envelope envelope
    on envelope.participant_id=assignment.participant_id
   and envelope.authority_envelope_id=assignment.authority_envelope_id
 where credential.participant_id=$1
   and credential.audience=$3
   and credential.kind='WORKLOAD_MTLS'
   and credential.state='ACTIVE'
   and credential.valid_from<=clock_timestamp()
   and credential.valid_until>clock_timestamp()
   and principal.kind='WORKLOAD'
   and principal.state='ACTIVE'
   and assignment.state='ACTIVE'
   and assignment.valid_during @> clock_timestamp()
   and $2::text=any(assignment.privacy_domain_ids)
   and $4::text=any(assignment.runtime_capability_ids)
   and (assignment.authority_group_id is null or
        openpc.assignment_group_permits(assignment.participant_id,assignment.authority_group_id,
                                        assignment.principal_id,assignment.valid_during))
   and role.state='ACTIVE'
   and envelope.state='ACTIVE'
   and envelope.valid_from<=clock_timestamp()
   and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
   and $2::text=any(envelope.privacy_domain_ids)
   and $4::text=any(envelope.runtime_capability_ids)
   and not exists (
     select 1 from control.revocation revocation
      where revocation.participant_id=assignment.participant_id
        and revocation.effective_at<=clock_timestamp()
        and revocation.target_id in (
          assignment.assignment_id,assignment.authority_envelope_id,assignment.principal_id
        )
   )`;

/** Select only current, direct workload authority suitable for the contract
 * simulation preview. The returned identifiers disclose no authority outside
 * the administrator's already-authorized Participant/privacy context. */
export async function listContractSimulationAuthorities(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
): Promise<readonly SimulationAuthorityChoice[]> {
  const selected = await client.query<SimulationAuthorityChoice>(
    `select distinct assignment.assignment_id::text as "assignmentId",
            assignment.authority_envelope_id::text as "envelopeId",
            principal.principal_id::text as "principalId",role.role_id as "roleId",
            credential.audience as "workloadId",
            principal.display_label as "workloadDisplayLabel",role.display_name as "roleDisplayName"
       ${currentAuthority.replace('credential.audience=$3', 'credential.audience like $3')}
      order by "workloadId","assignmentId" limit 257`,
    [participantId, privacyDomainId, 'urn:openpc:workload:%', CALL_CAPABILITY],
  );
  if (selected.rows.length > 256) throw new ContractError('PC-POLICY-2005');
  return selected.rows;
}

export async function listSimulationWorkloads(
  client: PoolClient,
  participantId: string,
): Promise<readonly SimulationWorkload[]> {
  const selected = await client.query<SimulationWorkload>(
    `select distinct principal.principal_id::text as "principalId",
            credential.audience as "workloadId"
       from control.credential credential
       join control.principal principal
         on principal.participant_id=credential.participant_id
        and principal.principal_id=credential.principal_id
      where credential.participant_id=$1 and credential.kind='WORKLOAD_MTLS'
        and credential.state='ACTIVE' and credential.valid_from<=clock_timestamp()
        and credential.valid_until>clock_timestamp()
        and principal.kind='WORKLOAD' and principal.state='ACTIVE'
      order by credential.audience limit 257`,
    [participantId],
  );
  if (selected.rows.length > 256) throw new ContractError('PC-POLICY-2005');
  return selected.rows;
}

/** Resolve the selected workload and direct assignment at the Identity owner.
 * The human administrator remains the separately-authorized requester. */
export async function resolveContractSimulationAuthority(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  workloadId: string,
  assignmentId: string,
  evaluatedAtMs: number,
): Promise<ResolvedSimulationAuthority> {
  const selected = await client.query<SimulationAuthorityRow>(
    `select distinct assignment.assignment_id::text as "assignmentId",
            assignment.authority_envelope_id::text as "envelopeId",
            principal.principal_id::text as "principalId",role.role_id as "roleId",
            credential.audience as "workloadId"
       ${currentAuthority}
       and assignment.assignment_id=$5
      order by "assignmentId" limit 2`,
    [participantId, privacyDomainId, workloadId, CALL_CAPABILITY, assignmentId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined)
    throw new ContractError('PC-POLICY-2003', 'simulation workload authority unavailable');
  const prediction = await readWorkloadPolicyPrediction(
    client,
    participantId,
    privacyDomainId,
    workloadId,
    evaluatedAtMs,
  );
  if (BigInt(prediction.input.credentialValidUntilNs) <= BigInt(evaluatedAtMs) * 1_000_000n)
    throw new ContractError('PC-POLICY-2003', 'simulation workload credential unavailable');
  return {
    ...row,
    authorityDigest: prediction.input.sourceDigest,
    credentialValidUntilNs: prediction.input.credentialValidUntilNs,
    ...(prediction.nextTransitionNs === undefined
      ? {}
      : { nextTransitionNs: prediction.nextTransitionNs }),
  };
}
