import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';

export interface RecoveryQualification {
  readonly principalId: string;
  readonly credentialId: string;
  readonly principalEpoch: string;
  readonly credentialEpoch: string;
}

export async function qualifyRecoveryPrincipal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  value: RecoveryQualification,
) {
  const credential = await client.query<{ credential_epoch: string }>(
    `select credential.credential_epoch::text from control.credential credential
     join control.hardware_authenticator hardware on hardware.participant_id=credential.participant_id
       and hardware.credential_id=credential.credential_id and hardware.principal_id=credential.principal_id
     where credential.participant_id=$1 and credential.principal_id=$2 and credential.credential_id=$3
       and credential.kind='WEBAUTHN' and credential.state='ACTIVE' and credential.credential_epoch=$4
       and credential.valid_from<=clock_timestamp()
       and (credential.valid_until is null or credential.valid_until>clock_timestamp())`,
    [participantId, value.principalId, value.credentialId, value.credentialEpoch],
  );
  if (credential.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  const principal = await client.query<{ authority_epoch: string }>(
    `update control.principal set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and principal_id=$2 and kind='USER' and state='ACTIVE' and authority_epoch=$3 returning authority_epoch::text`,
    [participantId, value.principalId, value.principalEpoch],
  );
  if (principal.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  await client.query(
    `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='recovery-principal-qualified',
       row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
    [participantId, value.principalId],
  );
  const result = await client.query<{ row_version: string }>(
    `insert into control.recovery_principal(principal_id,participant_id,privacy_domain_id,credential_id,credential_epoch,principal_epoch,state)
     values ($1,$2,$3,$4,$5,$6,'ACTIVE')
     on conflict (principal_id) do update set credential_id=excluded.credential_id,credential_epoch=excluded.credential_epoch,
       principal_epoch=excluded.principal_epoch,state='ACTIVE',row_version=recovery_principal.row_version+1,updated_at=clock_timestamp()
     where recovery_principal.participant_id=excluded.participant_id and recovery_principal.privacy_domain_id=excluded.privacy_domain_id
       and recovery_principal.state='REVOKED' returning row_version::text`,
    [
      value.principalId,
      participantId,
      privacyDomainId,
      value.credentialId,
      credential.rows[0]!.credential_epoch,
      principal.rows[0]!.authority_epoch,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  return {
    ...value,
    principalEpoch: principal.rows[0]!.authority_epoch,
    state: 'ACTIVE' as const,
    assurance: 'RECOVERY_PRINCIPAL' as const,
    revision: result.rows[0]!.row_version,
  };
}

export async function assertQualifiedRecoveryPrincipal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
): Promise<string> {
  const result = await client.query<{ credential_id: string }>(
    `select qualification.credential_id from control.recovery_principal qualification
     join control.principal principal on principal.participant_id=qualification.participant_id and principal.principal_id=qualification.principal_id
       and principal.state='ACTIVE' and principal.authority_epoch=qualification.principal_epoch
     join control.credential credential on credential.participant_id=qualification.participant_id and credential.principal_id=qualification.principal_id
       and credential.credential_id=qualification.credential_id and credential.credential_epoch=qualification.credential_epoch
       and credential.state='ACTIVE' and credential.kind='WEBAUTHN' and credential.valid_from<=clock_timestamp()
       and (credential.valid_until is null or credential.valid_until>clock_timestamp())
     join control.hardware_authenticator hardware on hardware.participant_id=credential.participant_id
       and hardware.credential_id=credential.credential_id and hardware.principal_id=credential.principal_id
     where qualification.participant_id=$1 and qualification.privacy_domain_id=$2 and qualification.principal_id=$3 and qualification.state='ACTIVE'`,
    [participantId, privacyDomainId, principalId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  return result.rows[0]!.credential_id;
}

/** Extra restriction, never authority: all ordinary policy/envelope/session checks still apply. */
export async function assertRecoveryPrincipalAction(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly principalId: string;
    readonly privacyDomainId: string;
    readonly actionIntentId: string;
    readonly resourceId: string;
    readonly catalogOperationId?: string;
    readonly stepUpCandidateDigest?: string;
    readonly sessionId?: string;
  },
): Promise<void> {
  const executor = await client.query<{ registered: boolean }>(
    'select openpc.is_platform_recovery_executor($1) as registered',
    [input.principalId],
  );
  if (executor.rows[0]?.registered === true) {
    // Enrollment reserves this identity permanently for the separate ceremony,
    // including after revocation. An ordinary role cannot change its purpose.
    if (
      ![
        'ACT-IDENTITY_CREATE_SESSION-V1',
        'ACT-IDENTITY_DELETE_SESSION-V1',
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      ].includes(input.actionIntentId)
    )
      throw new IdentityKernelError('PC-IDENTITY-1007');
    return;
  }
  const registered = await client.query(
    'select 1 from control.recovery_principal where participant_id=$1 and principal_id=$2',
    [input.participantId, input.principalId],
  );
  if (registered.rowCount === 0) return;
  const sessionAction = [
    'ACT-IDENTITY_CREATE_SESSION-V1',
    'ACT-IDENTITY_DELETE_SESSION-V1',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  ].includes(input.actionIntentId);
  if (sessionAction) return;
  await assertQualifiedRecoveryPrincipal(
    client,
    input.participantId,
    input.privacyDomainId,
    input.principalId,
  );
  // The approval owner additionally checks its exact staged recovery candidate before insertion.
  if (
    input.actionIntentId === 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' &&
    input.resourceId === input.principalId
  )
    return;
  const action = await client.query<{ operation_class: string }>(
    'select operation_class from control.action_intent where action_intent_id=$1',
    [input.actionIntentId],
  );
  if (action.rows[0]?.operation_class === 'READ') {
    if (input.resourceId === input.principalId) return;
    const related = await client.query(
      `select 1 from control.recovery_challenge recovery
      where recovery.participant_id=$1 and recovery.privacy_domain_id=$2 and recovery.recovery_principal_id=$3
        and (recovery.recovery_challenge_id=$4 or recovery.principal_id=$4)
      union all select 1 from control.approval_request approval join control.mutation_candidate candidate
        on candidate.participant_id=approval.participant_id and candidate.privacy_domain_id=approval.privacy_domain_id
          and candidate.mutation_candidate_id=approval.subject_id and candidate.candidate_digest=approval.subject_digest
      where approval.participant_id=$1 and approval.privacy_domain_id=$2 and approval.maker_principal_id=$3 and approval.approval_request_id=$4
        and candidate.catalog_operation_id='ID-OP-RECOVERY-COMPLETE' and candidate.maker_principal_id=$3`,
      [input.participantId, input.privacyDomainId, input.principalId, input.resourceId],
    );
    if (related.rowCount === 0) throw new IdentityKernelError('PC-IDENTITY-1007');
    return;
  }
  let approvedCompletionChallenge = false;
  if (input.stepUpCandidateDigest && input.sessionId) {
    // A challenge grants no mutation authority. Its purpose must already be the
    // exact live completion candidate owned by this executor and session.
    const candidate = await client.query(
      `select 1 from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
       and maker_principal_id=$3 and maker_session_id=$4 and resource_id=$5
       and action_intent_id=$6 and catalog_operation_id='ID-OP-RECOVERY-COMPLETE'
       and candidate_digest=$7 and state='APPROVED' and expires_at>clock_timestamp()`,
      [
        input.participantId,
        input.privacyDomainId,
        input.principalId,
        input.sessionId,
        input.resourceId,
        input.actionIntentId,
        Buffer.from(input.stepUpCandidateDigest.slice(7), 'hex'),
      ],
    );
    approvedCompletionChallenge = candidate.rowCount === 1;
  }
  if (
    (!approvedCompletionChallenge && input.catalogOperationId !== 'ID-OP-RECOVERY-COMPLETE') ||
    input.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  ) {
    throw new IdentityKernelError('PC-IDENTITY-1007');
  }
  const lease = await client.query(
    `select 1 from control.recovery_challenge where participant_id=$1 and privacy_domain_id=$2 and recovery_principal_id=$3
     and recovery_challenge_id=$4 and (outcome='COMPLETED' or (outcome in ('CUSTODIAN_TWO_APPROVED','LEASE_ACTIVE') and expires_at>clock_timestamp()))`,
    [input.participantId, input.privacyDomainId, input.principalId, input.resourceId],
  );
  if (lease.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
}

export async function revokeRecoveryPrincipal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
) {
  const result = await client.query<{ row_version: string }>(
    `update control.recovery_principal set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and state='ACTIVE' returning row_version::text`,
    [participantId, privacyDomainId, principalId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1007');
  await client.query(
    `update control.principal set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2`,
    [participantId, principalId],
  );
  await client.query(
    `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='recovery-principal-revoked',row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
    [participantId, principalId],
  );
  return { principalId, state: 'REVOKED' as const, revision: result.rows[0]!.row_version };
}

export async function readRecoveryPrincipal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
) {
  const result = await client.query<{
    credential_id: string;
    state: string;
    row_version: string;
    principal_epoch: string;
    credential_epoch: string;
  }>(
    `select credential_id,state,row_version::text,principal_epoch::text,credential_epoch::text from control.recovery_principal where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3`,
    [participantId, privacyDomainId, principalId],
  );
  const row = result.rows[0];
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  let current = false;
  try {
    await assertQualifiedRecoveryPrincipal(client, participantId, privacyDomainId, principalId);
    current = true;
  } catch (error) {
    if (!(error instanceof IdentityKernelError)) throw error;
  }
  return {
    effect: {
      principalId,
      participantId,
      privacyDomainId,
      credentialId: row.credential_id,
      state: row.state,
      revision: row.row_version,
      principalEpoch: row.principal_epoch,
      credentialEpoch: row.credential_epoch,
      assurance: 'RECOVERY_PRINCIPAL',
      current,
    },
  };
}
