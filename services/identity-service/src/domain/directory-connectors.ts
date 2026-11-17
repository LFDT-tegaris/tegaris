import type { PoolClient } from 'pg';
import type { DirectoryConnectorCandidate } from '../contracts/directory-operations.js';
import { IdentityKernelError } from './identity-errors.js';
import { readPrincipal } from './principal-lifecycle.js';

interface ConnectorRow {
  connector_id: string;
  participant_id: string;
  profile_id: string;
  profile_digest: Buffer;
  display_name: string;
  state: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  mass_change_threshold: number;
  external_group_freshness_seconds: number;
  row_version: string;
  last_mutation_operation_id: string | null;
  created_at: Date;
  updated_at: Date;
}
function record(row: ConnectorRow | undefined) {
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    connectorId: row.connector_id,
    participantId: row.participant_id,
    profileId: row.profile_id,
    profileDigest: `sha256:${row.profile_digest.toString('hex')}`,
    displayName: row.display_name,
    state: row.state,
    massChangeThreshold: row.mass_change_threshold,
    externalGroupFreshnessSeconds: row.external_group_freshness_seconds,
    revision: String(row.row_version),
    operationId: row.last_mutation_operation_id,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}
export type DirectoryConnector = ReturnType<typeof record>;
/** Internal opaque lookup; both connector and membership authority are required before disclosure. */
export async function resolveDirectoryMember(
  client: PoolClient,
  participantId: string,
  connectorId: string,
  externalId: string,
) {
  const result = await client.query<{ principal_id: string }>(
    'select principal_id from control.directory_member where participant_id=$1 and connector_id=$2 and external_id=$3',
    [participantId, connectorId, externalId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.principal_id;
}
export async function readDirectoryMember(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  connectorId: string,
  externalId: string,
  principalId: string,
) {
  const result = await client.query<{
    state: string;
    provider_version: string;
    provider_modified_at: Date;
    observed_at: Date;
    row_version: string;
    last_mutation_operation_id: string;
  }>(
    `select state,provider_version,provider_modified_at,observed_at,row_version::text,last_mutation_operation_id from control.directory_member
      where participant_id=$1 and connector_id=$2 and external_id=$3 and principal_id=$4 for share`,
    [participantId, connectorId, externalId, principalId],
  );
  const row = result.rows[0];
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    binding: {
      participantId,
      connectorId,
      externalId,
      principalId,
      state: row.state,
      providerVersion: row.provider_version,
      providerModifiedAt: row.provider_modified_at.toISOString(),
      observedAt: row.observed_at.toISOString(),
      revision: row.row_version,
      operationId: row.last_mutation_operation_id,
    },
    membership: (await readPrincipal(client, participantId, privacyDomainId, principalId)).effect,
  };
}
export async function readDirectoryConnector(
  client: PoolClient,
  participantId: string,
  connectorId: string,
) {
  return record(
    (
      await client.query<ConnectorRow>(
        'select * from control.directory_connector where participant_id=$1 and connector_id=$2 for share',
        [participantId, connectorId],
      )
    ).rows[0],
  );
}
/** Called inside the existing governed Identity mutation transaction with a Participant write fence. */
export async function mutateDirectoryConnector(
  client: PoolClient,
  participantId: string,
  candidate: DirectoryConnectorCandidate,
  operationId: string,
) {
  const change = candidate.change;
  if (change.mutation === 'CREATE') {
    return record(
      (
        await client.query<ConnectorRow>(
          `insert into control.directory_connector
      (connector_id,participant_id,profile_id,profile_digest,display_name,mass_change_threshold,external_group_freshness_seconds,last_mutation_operation_id)
      values ($1,$2,$3,$4,$5,$6,$7,$8) returning *`,
          [
            change.connectorId,
            participantId,
            change.profileId,
            Buffer.from(candidate.profileDigest.slice(7), 'hex'),
            change.displayName,
            change.massChangeThreshold,
            change.externalGroupFreshnessSeconds,
            operationId,
          ],
        )
      ).rows[0],
    );
  }
  const current = await readDirectoryConnector(client, participantId, change.connectorId);
  if (
    current.profileDigest !== candidate.profileDigest ||
    current.state === 'RETIRED' ||
    (change.mutation === 'SUSPEND' && current.state !== 'ACTIVE') ||
    (change.mutation === 'RESUME' && current.state !== 'SUSPENDED')
  )
    throw new IdentityKernelError('PC-IDENTITY-1002');
  // Retirement ends reconciliation without deleting source history or silently revoking local authority.
  const next =
    change.mutation === 'RETIRE'
      ? 'RETIRED'
      : change.mutation === 'SUSPEND'
        ? 'SUSPENDED'
        : change.mutation === 'RESUME'
          ? 'ACTIVE'
          : current.state;
  return record(
    (
      await client.query<ConnectorRow>(
        `update control.directory_connector set display_name=$3,state=$4,
    mass_change_threshold=$5,external_group_freshness_seconds=$6,row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$7
    where participant_id=$1 and connector_id=$2 returning *`,
        [
          participantId,
          change.connectorId,
          change.mutation === 'CONFIGURE' ? change.displayName : current.displayName,
          next,
          change.mutation === 'CONFIGURE'
            ? change.massChangeThreshold
            : current.massChangeThreshold,
          change.mutation === 'CONFIGURE'
            ? change.externalGroupFreshnessSeconds
            : current.externalGroupFreshnessSeconds,
          operationId,
        ],
      )
    ).rows[0],
  );
}
