import type { PoolClient } from 'pg';
import { IdentityKernelError } from './identity-errors.js';

export interface PrincipalRecord {
  readonly principalId: string;
  readonly participantId: string;
  readonly displayLabel: string;
  readonly kind: 'USER' | 'WALLET' | 'WORKLOAD' | 'PLATFORM_OPERATOR';
  readonly state: 'PROVISIONED' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'OFFBOARDED';
  readonly identityEpoch: string;
}

export interface PrincipalReadback {
  readonly effect: PrincipalRecord & {
    readonly revision: string;
    readonly identitySubjectId?: string;
    readonly membershipId?: string;
  };
  readonly operationId: string | null;
}
export interface PrincipalProposal {
  readonly candidateDigest: string;
  readonly resourceId: string;
  readonly mutation: 'PROVISION' | 'ACTIVATE' | 'SUSPEND' | 'REMOVE';
  readonly expectedRevision: string;
  readonly state: string;
  readonly expiresAt: string;
  readonly proposedPrincipal: Pick<
    PrincipalRecord,
    'principalId' | 'participantId' | 'displayLabel' | 'kind' | 'state'
  >;
}

/** Resolve only inside the selected scope; the route must authorize the returned resource before disclosure. */
export async function resolvePrincipalProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
) {
  const rows = await client.query<{ resource_id: string }>(
    `select resource_id from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2
      and candidate_digest=$3 and catalog_operation_id in ('ID-OP-PRINCIPAL-PROVISION','ID-OP-PRINCIPAL-ACTIVATE','ID-OP-PRINCIPAL-SUSPEND','ID-OP-MEMBERSHIP-REMOVE') limit 2`,
    [participantId, privacyDomainId, Buffer.from(candidateDigest.slice(7), 'hex')],
  );
  if (rows.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return rows.rows[0]!.resource_id;
}

/** Caller fences current read authority on the exact principal resolved from the immutable candidate. */
export async function readPrincipalProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  candidateDigest: string,
): Promise<PrincipalProposal> {
  const result = await client.query<{
    catalog_operation_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: PrincipalRecord;
  }>(
    `select catalog_operation_id,expected_revision::text,state,expires_at,candidate_document
    from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3
      and candidate_digest=$4 and catalog_operation_id in ('ID-OP-PRINCIPAL-PROVISION','ID-OP-PRINCIPAL-ACTIVATE','ID-OP-PRINCIPAL-SUSPEND','ID-OP-MEMBERSHIP-REMOVE') for share`,
    [participantId, privacyDomainId, resourceId, Buffer.from(candidateDigest.slice(7), 'hex')],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  const value = result.rows[0]!;
  const mutation =
    value.catalog_operation_id === 'ID-OP-PRINCIPAL-PROVISION'
      ? 'PROVISION'
      : value.catalog_operation_id === 'ID-OP-PRINCIPAL-ACTIVATE'
        ? 'ACTIVATE'
        : value.catalog_operation_id === 'ID-OP-MEMBERSHIP-REMOVE'
          ? 'REMOVE'
          : 'SUSPEND';
  const principal =
    mutation === 'PROVISION'
      ? value.candidate_document
      : (await readPrincipal(client, participantId, privacyDomainId, resourceId)).effect;
  return {
    candidateDigest,
    resourceId,
    mutation,
    expectedRevision: value.expected_revision,
    state: value.state,
    expiresAt: value.expires_at.toISOString(),
    proposedPrincipal: {
      principalId: resourceId,
      participantId,
      displayLabel: principal.displayLabel,
      kind: principal.kind,
      state:
        mutation === 'PROVISION'
          ? 'PROVISIONED'
          : mutation === 'ACTIVATE'
            ? 'ACTIVE'
            : mutation === 'REMOVE'
              ? 'OFFBOARDED'
              : 'SUSPENDED',
    },
  };
}
interface PrincipalRow {
  principal_id: string;
  participant_id: string;
  display_label: string;
  kind: PrincipalRecord['kind'];
  state: PrincipalRecord['state'];
  authority_epoch: string;
  row_version: string;
  identity_subject_id?: string | null;
}
function record(row: PrincipalRow | undefined): PrincipalReadback['effect'] {
  if (row === undefined) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    principalId: row.principal_id,
    participantId: row.participant_id,
    displayLabel: row.display_label,
    kind: row.kind,
    state: row.state,
    identityEpoch: String(row.authority_epoch),
    revision: String(row.row_version),
    ...(row.identity_subject_id
      ? { identitySubjectId: row.identity_subject_id, membershipId: row.principal_id }
      : {}),
  };
}
/** The caller holds the target principal write fence and the governed mutation transaction. */
export async function activatePrincipal(
  client: PoolClient,
  participantId: string,
  principalId: string,
) {
  const result = await client.query<PrincipalRow>(
    `update control.principal set state='ACTIVE',authority_epoch=authority_epoch+1,
      row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and principal_id=$2 and state='PROVISIONED'
      returning *,authority_epoch::text,row_version::text`,
    [participantId, principalId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1002');
  return record(result.rows[0]);
}
/** The caller fences the exact read authority through commit; no provider or credential data is projected. */
export async function readPrincipal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  principalId: string,
): Promise<PrincipalReadback> {
  const result = await client.query<PrincipalRow & { operation_id: string | null }>(
    `select principal.*,principal.authority_epoch::text,principal.row_version::text,membership.identity_subject_id,
      candidate.consumed_operation_id::text operation_id from control.principal principal
      left join control.participant_membership membership on membership.participant_id=principal.participant_id
        and membership.membership_id=principal.principal_id
      left join lateral (select consumed_operation_id from control.mutation_candidate
        where participant_id=principal.participant_id and privacy_domain_id=$3 and resource_id=principal.principal_id
          and catalog_operation_id in ('ID-OP-PRINCIPAL-PROVISION','ID-OP-PRINCIPAL-ACTIVATE','ID-OP-PRINCIPAL-SUSPEND','ID-OP-MEMBERSHIP-REMOVE')
          and state='CONSUMED' and expected_revision=principal.row_version-1
        order by created_at desc limit 1) candidate on true
      where principal.participant_id=$1 and principal.principal_id=$2`,
    [participantId, principalId, privacyDomainId],
  );
  return { effect: record(result.rows[0]), operationId: result.rows[0]!.operation_id };
}
