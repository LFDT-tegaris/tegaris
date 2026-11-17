import { directoryGroupObservationSchema } from '../contracts/directory-group-observation.js';
import type { DirectoryConnector } from './directory-connectors.js';
import type { DirectoryProfileRegistry } from './directory-profiles.js';
import { IdentityKernelError } from './identity-errors.js';
import { scimGroupObservationSchema } from './scim-directory-source.js';

/** The supplied read performs the real authorization fence on both sides of network
 * I/O. Never hold a database transaction open while awaiting the external source. */
export async function observeDirectoryGroup(
  participantId: string,
  connectorId: string,
  externalId: string,
  profiles: DirectoryProfileRegistry,
  readConnector: () => Promise<DirectoryConnector>,
) {
  const before = await readConnector();
  if (
    before.participantId !== participantId ||
    before.connectorId !== connectorId ||
    before.state !== 'ACTIVE'
  )
    throw new IdentityKernelError('PC-IDENTITY-1002');
  const profile = profiles.get(participantId, before.profileId, before.profileDigest);
  // Conservatively start freshness before the external request, never after a slow response.
  const observedAt = new Date(),
    freshUntil = new Date(observedAt.getTime() + before.externalGroupFreshnessSeconds * 1000);
  let source;
  try {
    source = scimGroupObservationSchema.parse(await profile.source.read('Groups', externalId));
    if (
      source.id !== externalId ||
      source.members === null ||
      source.members.some((member) => member.type !== 'User') ||
      new Set(source.members.map((member) => member.id)).size !== source.members.length
    )
      throw new Error('Incomplete direct membership');
    source.members.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  } catch {
    // Missing resources, absent members and nested/unknown types never mean empty membership.
    throw new IdentityKernelError('PC-AUTH-0002');
  }
  const after = await readConnector();
  if (
    after.participantId !== participantId ||
    after.connectorId !== connectorId ||
    after.state !== 'ACTIVE' ||
    after.revision !== before.revision ||
    after.profileDigest !== before.profileDigest
  )
    throw new IdentityKernelError('PC-IDENTITY-1001');
  profiles.get(participantId, after.profileId, after.profileDigest);
  const now = Date.now();
  if (
    now < observedAt.getTime() ||
    now >= freshUntil.getTime() ||
    Date.parse(source.lastModified) > now
  )
    throw new IdentityKernelError('PC-AUTH-0002');
  return directoryGroupObservationSchema.parse({
    participantId,
    connectorId,
    connectorRevision: before.revision,
    profileDigest: before.profileDigest,
    observedAt: observedAt.toISOString(),
    freshUntil: freshUntil.toISOString(),
    externalGroupFreshnessSeconds: before.externalGroupFreshnessSeconds,
    massChangeThreshold: before.massChangeThreshold,
    source,
  });
}
