'use client';
import { z } from 'zod';
import { directoryGroupCandidate, directoryGroupReadback } from '../lib/directory-group-workflow';

export function DirectoryGroupCandidate({
  candidate,
}: {
  candidate: z.infer<typeof directoryGroupCandidate>;
}) {
  return (
    <div className="grid gap-2 [overflow-wrap:anywhere]">
      <p>
        Change:{' '}
        {candidate.mutation === 'MAP_DIRECTORY' ? 'Map directory group' : 'Refresh directory group'}
      </p>
      <p>Local group: {candidate.groupId}</p>
      <p>Connector: {candidate.connectorId}</p>
      <p>Exact provider group: {candidate.externalGroupId}</p>
      <p>Provider name: {candidate.observation.source.displayName}</p>
      <p>Provider version: {candidate.observation.source.version}</p>
      <p>
        Review class: {candidate.reviewClass === 'MASS_CHANGE' ? 'Mass change' : 'Ordinary change'}
      </p>
      <p>
        {candidate.changedMembers} membership changes; {candidate.managedMembers} current members.
      </p>
      <p>Observed: {candidate.observation.observedAt}</p>
      <p>Fresh until: {candidate.observation.freshUntil}</p>
      <p>
        Only the listed direct members will remain in this mapped group. Removed members lose
        group-constrained grants and delegations. Rejoining does not restore revoked grants.
      </p>
      <p>
        Membership alone grants no permissions. Existing explicit grants stop authorizing when this
        observation expires.
      </p>
      {candidate.members.length === 0 ? (
        <p>The provider explicitly returned an empty group.</p>
      ) : (
        <ul className="grid gap-1 list-inside list-disc">
          {candidate.members.map((member) => (
            <li key={member.externalId}>
              Provider member {member.externalId} → local principal {member.principalId}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function DirectoryGroupResult({ value }: { value: z.infer<typeof directoryGroupReadback> }) {
  const { group, mapping } = value;
  return (
    <div aria-label="Directory group result" className="grid gap-2 [overflow-wrap:anywhere]">
      <p>Local group: {group.effect.groupName}</p>
      <p>Group ID: {group.effect.groupId}</p>
      <p>
        State: {group.effect.state} · revision {group.effect.revision}
      </p>
      <p>Operation: {group.effect.operationId}</p>
      {mapping ? (
        <>
          <p>Connector: {mapping.connectorId}</p>
          <p>Provider group: {mapping.externalGroupId}</p>
          <p>Freshness: {mapping.fresh ? 'Current' : 'Stale — group authority denied'}</p>
          <p>Fresh until: {mapping.freshUntil}</p>
          <p>Provider version: {mapping.providerVersion}</p>
          <p>Mapping revision: {mapping.revision}</p>
        </>
      ) : (
        <p>This local group has no directory mapping.</p>
      )}
      {group.members.length === 0 ? (
        <p>No membership history on this page.</p>
      ) : (
        <ul className="grid gap-1 list-inside list-disc">
          {group.members.map((member) => (
            <li key={member.memberId}>
              {member.displayName} · {member.principalId} · {member.state} ·{' '}
              {member.current ? 'Current' : 'Not current'}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
