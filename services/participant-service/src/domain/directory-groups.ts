import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../../../identity-service/src/contracts/authorization.js';
import type { DirectoryGroupObservation } from '../../../identity-service/src/contracts/directory-group-observation.js';
import { readDirectoryConnector } from '../../../identity-service/src/domain/directory-connectors.js';
import { directoryReviewClass } from '../../../identity-service/src/domain/directory-reconciliation.js';
import {
  directoryGroupCandidateSchema,
  type DirectoryGroupCandidate,
  type DirectoryGroupChange,
} from '../contracts/directory-group-operations.js';
import { readGroup, revokeLinkedAssignments } from './group-lifecycle.js';
import { ParticipantKernelError } from './participant-errors.js';

interface MappingRow {
  connector_id: string;
  external_group_id: string;
  profile_digest: Buffer;
  provider_version: string;
  provider_modified_at: Date;
  source_digest: Buffer;
  observed_at: Date;
  fresh_until: Date;
  row_version: string;
  last_mutation_operation_id: string;
  fresh: boolean;
}
async function mapping(client: PoolClient, participantId: string, groupId: string) {
  const result = await client.query<MappingRow>(
    `select m.*,
    least(m.fresh_until,m.observed_at+make_interval(secs=>c.external_group_freshness_seconds)) fresh_until,
    (g.state='ACTIVE' and openpc.directory_group_permits(m.participant_id,m.authority_group_id)) fresh
    from control.directory_group_mapping m join control.directory_connector c on c.participant_id=m.participant_id and c.connector_id=m.connector_id
    join control.authority_group g on g.participant_id=m.participant_id and g.authority_group_id=m.authority_group_id
    where m.participant_id=$1 and m.authority_group_id=$2 for share of m,c,g`,
    [participantId, groupId],
  );
  return result.rows[0];
}
function projection(row: MappingRow | undefined) {
  return row
    ? {
        connectorId: row.connector_id,
        externalGroupId: row.external_group_id,
        profileDigest: `sha256:${row.profile_digest.toString('hex')}`,
        providerVersion: row.provider_version,
        providerModifiedAt: row.provider_modified_at.toISOString(),
        observedAt: row.observed_at.toISOString(),
        freshUntil: row.fresh_until.toISOString(),
        fresh: row.fresh,
        revision: String(row.row_version),
        operationId: row.last_mutation_operation_id,
      }
    : null;
}
export async function readDirectoryGroup(
  client: PoolClient,
  participantId: string,
  groupId: string,
  cursor?: string,
) {
  return {
    group: await readGroup(client, participantId, groupId, cursor),
    mapping: projection(await mapping(client, participantId, groupId)),
  };
}
export async function prepareDirectoryGroup(
  client: PoolClient,
  participantId: string,
  change: DirectoryGroupChange,
  expectedRevision: string,
  observation: DirectoryGroupObservation,
): Promise<DirectoryGroupCandidate> {
  const group = (await readGroup(client, participantId, change.groupId)).effect;
  const connector = await readDirectoryConnector(client, participantId, change.connectorId);
  const currentMapping = await mapping(client, participantId, change.groupId);
  if (
    group.state !== 'ACTIVE' ||
    group.revision !== expectedRevision ||
    observation.participantId !== participantId ||
    observation.connectorId !== connector.connectorId ||
    observation.connectorRevision !== connector.revision ||
    observation.profileDigest !== connector.profileDigest ||
    observation.massChangeThreshold !== connector.massChangeThreshold ||
    observation.externalGroupFreshnessSeconds !== connector.externalGroupFreshnessSeconds ||
    connector.state !== 'ACTIVE' ||
    observation.source.id !== change.externalGroupId
  )
    throw new ParticipantKernelError('PC-IDENTITY-1001');
  if (
    (change.mutation === 'MAP_DIRECTORY') !== (currentMapping === undefined) ||
    (currentMapping &&
      (currentMapping.connector_id !== change.connectorId ||
        currentMapping.external_group_id !== change.externalGroupId ||
        !currentMapping.profile_digest.equals(
          Buffer.from(observation.profileDigest.slice(7), 'hex'),
        )))
  )
    throw new ParticipantKernelError('PC-IDENTITY-1002');
  const existing = await client.query<{ principal_id: string }>(
    `select principal_id from control.authority_group_member
    where participant_id=$1 and authority_group_id=$2 and state='ACTIVE' and valid_during @> clock_timestamp() limit 10001`,
    [participantId, change.groupId],
  );
  if (existing.rows.length > 10000) throw new ParticipantKernelError('PC-IDENTITY-1004');
  if (!currentMapping) {
    const occupied = await client.query(
      `select 1 from control.authority_group_member where participant_id=$1 and authority_group_id=$2 and state in ('ACTIVE','SUSPENDED')
      union all select 1 from control.assignment where participant_id=$1 and authority_group_id=$2 and state in ('ACTIVE','SUSPENDED') limit 1`,
      [participantId, change.groupId],
    );
    if (occupied.rowCount) throw new ParticipantKernelError('PC-IDENTITY-1002');
  }
  const found = await client.query<{
    external_id: string;
    principal_id: string;
    principal_revision: string;
    member_revision: string;
  }>(
    `select m.external_id,m.principal_id,p.row_version::text principal_revision,m.row_version::text member_revision
    from control.directory_member m join control.principal p on p.participant_id=m.participant_id and p.principal_id=m.principal_id
    join control.participant_membership binding on binding.participant_id=m.participant_id and binding.membership_id=m.principal_id
    where m.participant_id=$1 and m.connector_id=$2 and m.external_id=any($3::text[]) and m.state='LINKED' and p.state='ACTIVE' and p.kind='USER'
    for share of m,p,binding`,
    [participantId, change.connectorId, observation.source.members.map((member) => member.id)],
  );
  const byExternalId = new Map(found.rows.map((row) => [row.external_id, row]));
  const members = observation.source.members.map((source) => {
    const row = byExternalId.get(source.id);
    if (!row) throw new ParticipantKernelError('PC-IDENTITY-1002');
    return {
      externalId: source.id,
      principalId: row.principal_id,
      principalRevision: row.principal_revision,
      directoryMemberRevision: row.member_revision,
    };
  });
  const oldIds = new Set(existing.rows.map((row) => row.principal_id)),
    newIds = new Set(members.map((member) => member.principalId));
  const changedMembers =
    [...oldIds].filter((id) => !newIds.has(id)).length +
    [...newIds].filter((id) => !oldIds.has(id)).length;
  return directoryGroupCandidateSchema.parse({
    ...change,
    expectedRevision,
    observation,
    members,
    managedMembers: oldIds.size,
    changedMembers,
    reviewClass: directoryReviewClass(oldIds.size, changedMembers, connector.massChangeThreshold),
  });
}

/** Called by the ordinary approved mutation owner under its Participant write fence. */
export async function projectDirectoryGroup(
  client: PoolClient,
  participantId: string,
  makerId: string,
  candidate: DirectoryGroupCandidate,
  operationId: string,
) {
  const prepared = await prepareDirectoryGroup(
    client,
    participantId,
    {
      mutation: candidate.mutation,
      groupId: candidate.groupId,
      connectorId: candidate.connectorId,
      externalGroupId: candidate.externalGroupId,
    },
    candidate.expectedRevision,
    candidate.observation,
  );
  if (canonicalAuthorizationDigest(prepared) !== canonicalAuthorizationDigest(candidate))
    throw new ParticipantKernelError('PC-IDENTITY-1001');
  const source = candidate.observation.source,
    observation = candidate.observation;
  const values = [
    participantId,
    candidate.groupId,
    candidate.connectorId,
    candidate.externalGroupId,
    Buffer.from(observation.profileDigest.slice(7), 'hex'),
    source.version,
    source.lastModified,
    Buffer.from(canonicalAuthorizationDigest(source).slice(7), 'hex'),
    source.members.map((member) => member.id),
    observation.observedAt,
    observation.freshUntil,
    operationId,
  ];
  if (candidate.mutation === 'MAP_DIRECTORY')
    await client.query(
      `insert into control.directory_group_mapping
    (participant_id,authority_group_id,connector_id,external_group_id,profile_digest,provider_version,provider_modified_at,source_digest,source_member_ids,observed_at,fresh_until,last_mutation_operation_id)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      values,
    );
  else
    await client.query(
      `update control.directory_group_mapping set provider_version=$6,provider_modified_at=$7,source_digest=$8,source_member_ids=$9,
    observed_at=$10,fresh_until=$11,last_mutation_operation_id=$12,row_version=row_version+1,updated_at=clock_timestamp()
    where participant_id=$1 and authority_group_id=$2 and connector_id=$3 and external_group_id=$4 and profile_digest=$5`,
      values,
    );
  const principalIds = candidate.members.map((member) => member.principalId);
  const removed = await client.query<{ principal_id: string }>(
    `update control.authority_group_member set state='REVOKED',revoked_at=clock_timestamp()
    where participant_id=$1 and authority_group_id=$2 and state in ('ACTIVE','SUSPENDED') and not (principal_id=any($3::uuid[])) returning principal_id`,
    [participantId, candidate.groupId, principalIds],
  );
  const revokedAssignments = removed.rows.length
    ? await revokeLinkedAssignments(
        client,
        participantId,
        candidate.groupId,
        makerId,
        operationId,
        removed.rows.map((row) => row.principal_id),
      )
    : 0;
  await client.query(
    `update control.authority_group_member set state='EXPIRED',revoked_at=clock_timestamp()
    where participant_id=$1 and authority_group_id=$2 and state='ACTIVE' and upper(valid_during)<=clock_timestamp()`,
    [participantId, candidate.groupId],
  );
  await client.query(
    `insert into control.authority_group_member(participant_id,authority_group_id,principal_id,valid_during,state)
    select $1,$2,id,tstzrange(clock_timestamp(),null,'[)'),'ACTIVE' from unnest($3::uuid[]) id
    where not exists (select from control.authority_group_member m where m.participant_id=$1 and m.authority_group_id=$2 and m.principal_id=id and m.state='ACTIVE')`,
    [participantId, candidate.groupId, principalIds],
  );
  await client.query(
    `update control.authority_group set row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
    where participant_id=$1 and authority_group_id=$2`,
    [participantId, candidate.groupId, operationId],
  );
  return {
    ...(await readDirectoryGroup(client, participantId, candidate.groupId)),
    revokedAssignments,
  };
}
