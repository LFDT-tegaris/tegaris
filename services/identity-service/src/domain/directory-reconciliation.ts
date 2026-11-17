import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { DirectoryReconciliationCandidate } from '../contracts/directory-operations.js';
import { readDirectoryConnector } from './directory-connectors.js';
import { createInitialHumanMembership } from './human-identity.js';
import { removeMembership, membershipRemovalFence } from './membership-removal.js';
import { IdentityKernelError } from './identity-errors.js';
import { lockAuthorityFence, type AuthorityFence } from '../db/authority-fence.js';
import type { RegisteredDirectoryProfile } from './directory-profiles.js';

interface MemberRow {
  external_id: string;
  principal_id: string;
  oidc_credential_id: string;
  state: string;
  provider_version: string;
  provider_modified_at: Date;
  source_digest: Buffer;
  principal_state: string;
  principal_revision: string;
  display_label: string;
}
export async function directoryReconciliationContext(
  client: PoolClient,
  participantId: string,
  connectorId: string,
  externalIds: readonly string[],
) {
  const connector = await readDirectoryConnector(client, participantId, connectorId);
  const members = await client.query<MemberRow>(
    `select m.*,p.state principal_state,p.row_version::text principal_revision,p.display_label
    from control.directory_member m join control.principal p on p.participant_id=m.participant_id and p.principal_id=m.principal_id
    where m.participant_id=$1 and m.connector_id=$2 and m.external_id=any($3::text[]) for share of m,p`,
    [participantId, connectorId, externalIds],
  );
  const count = await client.query<{ total: string }>(
    `select count(*)::text total from control.directory_member where participant_id=$1 and connector_id=$2 and state='LINKED'`,
    [participantId, connectorId],
  );
  return { connector, members: members.rows, managedMembers: Number(count.rows[0]!.total) };
}
export function directoryChangeCount(
  context: Awaited<ReturnType<typeof directoryReconciliationContext>>,
  members: DirectoryReconciliationCandidate['members'],
) {
  let changed = 0;
  for (const member of members) {
    const bound = context.members.find((value) => value.external_id === member.externalId);
    if (
      !bound ||
      (!member.source.active && bound.state === 'LINKED') ||
      (member.source.active && bound.display_label !== member.displayName)
    )
      changed++;
  }
  return changed;
}
export function directoryReviewClass(managed: number, changed: number, threshold: number) {
  return changed * 100 > Math.max(1, managed) * threshold
    ? ('MASS_CHANGE' as const)
    : ('ORDINARY' as const);
}
export async function directoryReconciliationFence(
  client: PoolClient,
  participantId: string,
  candidate: DirectoryReconciliationCandidate,
): Promise<AuthorityFence> {
  await lockAuthorityFence(client, participantId, {
    participant: [{ id: participantId, write: true }],
  });
  const fence: Record<string, { id: string; write?: boolean }[]> = {
    participant: [{ id: participantId, write: true }],
    principal: candidate.members
      .filter((member) => member.expectedPrincipalRevision !== '0')
      .map((member) => ({ id: member.principalId, write: true })),
  };
  for (const member of candidate.members)
    if (!member.source.active && member.expectedPrincipalRevision !== '0') {
      const removal = await membershipRemovalFence(client, participantId, member.principalId);
      for (const [kind, rows] of Object.entries(removal))
        if (rows) (fence[kind] ??= []).push(...rows);
    }
  return fence as AuthorityFence;
}

/** Provider observations are evidence; this transaction remains the sole local identity authority. */
export async function reconcileDirectoryMembers(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  makerId: string,
  candidate: DirectoryReconciliationCandidate,
  profile: RegisteredDirectoryProfile,
  operationId: string,
) {
  const context = await directoryReconciliationContext(
    client,
    participantId,
    candidate.connectorId,
    candidate.members.map((member) => member.externalId),
  );
  const changed = directoryChangeCount(context, candidate.members);
  if (
    context.connector.state !== 'ACTIVE' ||
    context.connector.profileDigest !== candidate.profileDigest ||
    context.connector.revision !== candidate.expectedRevision ||
    context.managedMembers !== candidate.managedMembers ||
    changed !== candidate.changedMembers ||
    directoryReviewClass(context.managedMembers, changed, context.connector.massChangeThreshold) !==
      candidate.reviewClass
  )
    throw new IdentityKernelError('PC-IDENTITY-1001');
  const time = await client.query<{ now: Date }>('select clock_timestamp() now');
  const now = time.rows[0]!.now.getTime(),
    observed = Date.parse(candidate.observedAt);
  if (
    observed > now ||
    now - observed > Math.min(300, context.connector.externalGroupFreshnessSeconds) * 1000
  )
    throw new IdentityKernelError('PC-AUTH-0002');
  const effects: { principalId: string; state: string; revision: string; externalId: string }[] =
    [];
  for (const member of candidate.members) {
    const bound = context.members.find((value) => value.external_id === member.externalId);
    const sourceDigest = Buffer.from(canonicalAuthorizationDigest(member.source).slice(7), 'hex');
    if ((candidate.mode === 'PROVISION') !== (bound === undefined))
      throw new IdentityKernelError('PC-IDENTITY-1002');
    if (
      member.source.id !== member.externalId ||
      Date.parse(member.source.lastModified) > now ||
      member.externalId.length > 255 ||
      (bound &&
        (bound.principal_id !== member.principalId ||
          bound.principal_revision !== member.expectedPrincipalRevision ||
          bound.state !== 'LINKED' ||
          ['REVOKED', 'OFFBOARDED'].includes(bound.principal_state) ||
          bound.provider_modified_at.getTime() > Date.parse(member.source.lastModified) ||
          (bound.provider_version === member.source.version &&
            !bound.source_digest.equals(sourceDigest))))
    )
      throw new IdentityKernelError('PC-IDENTITY-1002');
    if (!bound) {
      if (
        member.expectedPrincipalRevision !== '0' ||
        !member.source.active ||
        member.principalId === makerId
      )
        throw new IdentityKernelError('PC-IDENTITY-1002');
      // The registered provider explicitly binds its SCIM ID to OIDC sub; no email/label inference.
      const existing = await client.query(
        `select 1 from control.credential where participant_id=$1 and kind='OIDC_SUBJECT' and issuer=$2 and subject=$3 and audience=$4 limit 1`,
        [participantId, profile.oidcIssuer, member.externalId, profile.oidcClientId],
      );
      if (existing.rowCount) throw new IdentityKernelError('PC-IDENTITY-1002');
      await client.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'USER',$3,'PROVISIONED',1)`,
        [member.principalId, participantId, member.displayName],
      );
      await createInitialHumanMembership(client, {
        principalId: member.principalId,
        participantId,
        displayLabel: member.displayName,
        kind: 'USER',
        state: 'PROVISIONED',
        identityEpoch: '1',
      });
      const credential = await client.query<{ credential_id: string }>(
        `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from)
        values($1,$2,'OIDC_SUBJECT',$3,$4,$5,'ACTIVE',1,clock_timestamp()) returning credential_id`,
        [
          participantId,
          member.principalId,
          profile.oidcIssuer,
          member.externalId,
          profile.oidcClientId,
        ],
      );
      await client.query(
        `insert into control.directory_member(participant_id,connector_id,external_id,principal_id,oidc_credential_id,provider_version,provider_modified_at,observed_at,source_digest,last_mutation_operation_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          participantId,
          candidate.connectorId,
          member.externalId,
          member.principalId,
          credential.rows[0]!.credential_id,
          member.source.version,
          member.source.lastModified,
          candidate.observedAt,
          sourceDigest,
          operationId,
        ],
      );
      effects.push({
        principalId: member.principalId,
        externalId: member.externalId,
        state: 'PROVISIONED',
        revision: '1',
      });
      continue;
    }
    let state = bound.principal_state,
      revision = bound.principal_revision;
    if (!member.source.active) {
      const removed = await removeMembership(
        client,
        participantId,
        privacyDomainId,
        member.principalId,
        makerId,
        operationId,
      );
      state = removed.state;
      revision = removed.revision;
    } else if (bound.display_label !== member.displayName) {
      const updated = await client.query<{ row_version: string }>(
        `update control.principal set display_label=$3,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2 returning row_version::text`,
        [participantId, member.principalId, member.displayName],
      );
      revision = updated.rows[0]!.row_version;
    }
    await client.query(
      `update control.directory_member set state=$4,provider_version=$5,provider_modified_at=$6,observed_at=$7,source_digest=$8,row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$9
      where participant_id=$1 and connector_id=$2 and external_id=$3`,
      [
        participantId,
        candidate.connectorId,
        member.externalId,
        member.source.active ? 'LINKED' : 'OFFBOARDED',
        member.source.version,
        member.source.lastModified,
        candidate.observedAt,
        sourceDigest,
        operationId,
      ],
    );
    effects.push({
      principalId: member.principalId,
      externalId: member.externalId,
      state,
      revision,
    });
  }
  await client.query(
    `update control.directory_connector set row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3 where participant_id=$1 and connector_id=$2`,
    [participantId, candidate.connectorId, operationId],
  );
  return {
    connector: await readDirectoryConnector(client, participantId, candidate.connectorId),
    members: effects,
  };
}
