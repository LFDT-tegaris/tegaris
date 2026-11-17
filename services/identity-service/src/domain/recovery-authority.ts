import type { PoolClient } from 'pg';
import { assertQualifiedRecoveryPrincipal } from './recovery-principal.js';

import type { AuthorityFence, BoundAuthority } from '../db/authority-fence.js';
import { approvalAuthorityDependencies } from '../db/approval-authority-fence.js';
import { principalInvalidationFence } from '../db/principal-invalidation-fence.js';
import { IdentityKernelError } from './identity-errors.js';

export interface RecoveryPrincipals {
  readonly subjectId: string;
  readonly recoveryPrincipalId: string;
  readonly custodianPrincipalIds: readonly [string, string];
}

interface CustodySignerAuthority extends BoundAuthority {
  readonly signerCredentialId: string;
  readonly signerCredentialEpoch: string;
}

export interface CustodianAuthority extends CustodySignerAuthority {
  readonly checkerAuthority: CustodySignerAuthority;
}

export interface RecoveryAuthorityRow {
  readonly custodian_one_approved_at: Date | null;
  readonly custodian_two_approved_at: Date | null;
  readonly custodian_one_authority: CustodianAuthority | null;
  readonly custodian_two_authority: CustodianAuthority | null;
  readonly principal_id: string;
  readonly recovery_principal_id: string;
  readonly custodian_one_principal_id: string | null;
  readonly custodian_two_principal_id: string | null;
  readonly current_epoch: string;
  readonly recovery_principal_epoch: string | null;
  readonly custodian_one_epoch: string | null;
  readonly custodian_two_epoch: string | null;
}

export function recoveryPrincipalIds(value: RecoveryPrincipals): readonly string[] {
  const ids = [value.subjectId, value.recoveryPrincipalId, ...value.custodianPrincipalIds];
  if (new Set(ids).size !== 4) throw new IdentityKernelError('PC-IDENTITY-1007');
  return ids;
}

/** Called under the shared authority fence, before a recovery business transition. */
export async function currentRecoveryEpochs(
  client: PoolClient,
  participantId: string,
  value: RecoveryPrincipals,
): Promise<readonly string[]> {
  const ids = recoveryPrincipalIds(value);
  const result = await client.query<{ principal_id: string; authority_epoch: string }>(
    `select principal_id::text,authority_epoch::text from control.principal
      where participant_id=$1 and principal_id=any($2::uuid[]) and state='ACTIVE'`,
    [participantId, ids],
  );
  if (result.rowCount !== 4) throw new IdentityKernelError('PC-IDENTITY-1007');
  return ids.map((id) => result.rows.find((row) => row.principal_id === id)!.authority_epoch);
}

function rowPrincipals(row: RecoveryAuthorityRow): RecoveryPrincipals {
  if (row.custodian_one_principal_id === null || row.custodian_two_principal_id === null) {
    throw new IdentityKernelError('PC-IDENTITY-1007');
  }
  return {
    subjectId: row.principal_id,
    recoveryPrincipalId: row.recovery_principal_id,
    custodianPrincipalIds: [row.custodian_one_principal_id, row.custodian_two_principal_id],
  };
}

export async function assertRecoveryAuthority(
  client: PoolClient,
  participantId: string,
  row: RecoveryAuthorityRow,
): Promise<void> {
  for (const authority of custodians(row)) {
    const credential = await client.query(
      `select 1 from control.credential where participant_id=$1 and principal_id=$2 and credential_id=$3 and credential_epoch=$4
      and kind='WEBAUTHN' and state='ACTIVE' and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())`,
      [
        participantId,
        authority.principalId,
        authority.signerCredentialId,
        authority.signerCredentialEpoch,
      ],
    );
    if (credential.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  }
  const expected = [
    row.current_epoch,
    row.recovery_principal_epoch,
    row.custodian_one_epoch,
    row.custodian_two_epoch,
  ];
  const current = await currentRecoveryEpochs(client, participantId, rowPrincipals(row));
  // Historical leases without captured authority must be restarted through the owner.
  if (expected.some((epoch, index) => epoch === null || epoch !== current[index])) {
    throw new IdentityKernelError('PC-IDENTITY-1007');
  }
}

/** Discover every principal before the shared owner takes ordered locks. */
export async function recoveryAuthorityFence(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  recoveryId: string,
  completing = false,
): Promise<AuthorityFence & { readonly authorities: readonly BoundAuthority[] }> {
  const result = await client.query<RecoveryAuthorityRow>(
    `select * from control.recovery_challenge where participant_id=$1 and recovery_challenge_id=$2 and privacy_domain_id=$3`,
    [participantId, recoveryId, privacyDomainId],
  );
  const row = result.rows[0];
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1007');
  const ids = recoveryPrincipalIds(rowPrincipals(row));
  const credentialId = await assertQualifiedRecoveryPrincipal(
    client,
    participantId,
    privacyDomainId,
    row.recovery_principal_id,
  );
  const invalidation = completing
    ? await principalInvalidationFence(client, participantId, row.principal_id, true)
    : {};
  const authorities = custodians(row);
  return {
    authorities,
    ...invalidation,
    credential: [
      { id: credentialId },
      ...authorities.map((authority) => ({ id: authority.signerCredentialId })),
      ...(invalidation.credential ?? []),
    ],
    principal: [...ids.map((id) => ({ id })), ...(invalidation.principal ?? [])],
  };
}

function custodians(row: RecoveryAuthorityRow): readonly CustodySignerAuthority[] {
  const values = [
    [row.custodian_one_approved_at, row.custodian_one_authority, row.custodian_one_principal_id],
    [row.custodian_two_approved_at, row.custodian_two_authority, row.custodian_two_principal_id],
  ] as const;
  return values.flatMap(([approved, authority, principalId]) => {
    if (!approved) {
      if (authority) throw new IdentityKernelError('PC-IDENTITY-1007');
      return [];
    }
    if (
      !authority ||
      authority.principalId !== principalId ||
      !authority.checkerAuthority ||
      [principalId, row.principal_id, row.recovery_principal_id].includes(
        authority.checkerAuthority.principalId,
      )
    )
      throw new IdentityKernelError('PC-IDENTITY-1007');
    return [authority, authority.checkerAuthority];
  });
}

/** Retain both governed approval paths and signature epochs until recovery execution. */
export async function captureCustodianAuthority(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly principalId: string;
    readonly recoveryId: string;
    readonly approvalRequestId: string;
    readonly signerCredentialId: string;
  },
): Promise<CustodianAuthority> {
  const result = await client.query<CustodySignerAuthority>(
    `select c.maker_principal_id::text "principalId",c.maker_session_id::text "sessionId",c.maker_session_epoch::text "sessionEpoch",
      c.maker_participant_epoch::text "participantEpoch",c.maker_principal_epoch::text "principalEpoch",
      c.maker_assignment_id::text "assignmentId",c.maker_assignment_row_version::text "assignmentRowVersion",
      c.maker_authority_envelope_id::text "authorityEnvelopeId",c.maker_authority_epoch::text "authorityEpoch",
      c.maker_delegation_epoch::text "delegationEpoch",c.privacy_domain_id::text "privacyDomainId",
      c.action_intent_id "actionIntentId",c.catalog_operation_id "catalogOperationId",c.resource_id::text "resourceId",
      credential.credential_id::text "signerCredentialId",credential.credential_epoch::text "signerCredentialEpoch"
     from control.approval_request approval join control.mutation_candidate c on c.participant_id=approval.participant_id
       and c.privacy_domain_id=approval.privacy_domain_id and c.mutation_candidate_id=approval.subject_id and c.candidate_digest=approval.subject_digest
     join control.credential credential on credential.participant_id=c.participant_id and credential.principal_id=c.maker_principal_id
       and credential.credential_id=$6 and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
     where approval.participant_id=$1 and approval.privacy_domain_id=$2 and approval.approval_request_id=$5
       and approval.state='APPROVED' and c.state='APPROVED' and c.maker_principal_id=$3 and c.resource_id=$4
       and c.catalog_operation_id='ID-OP-RECOVERY-APPROVE'`,
    [
      input.participantId,
      input.privacyDomainId,
      input.principalId,
      input.recoveryId,
      input.approvalRequestId,
      input.signerCredentialId,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  const dependencies = await approvalAuthorityDependencies(
    client,
    input,
    input.approvalRequestId,
    true,
  );
  const checker = dependencies.authorities[1];
  const signerId = dependencies.rows.credential?.[0]?.id;
  if (!checker || !signerId) throw new IdentityKernelError('PC-IDENTITY-1007');
  const credential = await client.query<{ credential_epoch: string }>(
    `select credential_epoch::text from control.credential where participant_id=$1 and principal_id=$2 and credential_id=$3 and state='ACTIVE' and kind='WEBAUTHN'`,
    [input.participantId, checker.principalId, signerId],
  );
  if (credential.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  return {
    ...result.rows[0]!,
    checkerAuthority: {
      ...checker,
      signerCredentialId: signerId,
      signerCredentialEpoch: credential.rows[0]!.credential_epoch,
    },
  };
}
