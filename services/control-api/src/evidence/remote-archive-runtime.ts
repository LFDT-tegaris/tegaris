import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import type { Pool } from 'pg';
import { z } from 'zod';
import {
  archiveHostTrust,
  RemoteArchiveAuthority,
  signedArchiveProfile,
} from './remote-archive-authority.js';
import { RemoteArchiveEvidenceReader } from './remote-archive-reader.js';
import { ProtectedRemoteArchiveCustody } from './protected-remote-custody.js';
import { RemoteArchiveCustody } from './remote-archive-custody.js';
import { PostgresRemoteArchiveAttemptOwner } from './remote-archive-owner.js';
import { RemoteArchiveError } from './remote-archive-contracts.js';
import type { EvidenceScope } from './segment.js';
import { s3ArchiveCredentials, type S3ArchiveCredentials } from './remote-archive-s3.js';

const path = z.string().refine(isAbsolute);
export const remoteArchiveRuntimeConfiguration = z.strictObject({
  trust: archiveHostTrust,
  signedProfileFile: path,
  receiptPrivateKeyFile: path,
  commitKeyFile: path,
  credentialsFile: path,
});

/** Mounted files are host-owned, non-symlink, bounded regular files with no
 * group/other access. No API request supplies a root, signer or credential path. */
async function secretFile(path: string, maximum: number, minimum = 1) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < minimum || stat.size > maximum || (stat.mode & 0o077) !== 0)
      throw new RemoteArchiveError('UNAVAILABLE');
    const bytes = await file.readFile();
    if (bytes.length < minimum || bytes.length > maximum)
      throw new RemoteArchiveError('UNAVAILABLE');
    return bytes;
  } finally {
    await file.close();
  }
}

export async function openRemoteArchiveRuntime(
  pool: Pool,
  configuration: z.infer<typeof remoteArchiveRuntimeConfiguration>,
  scopes: readonly EvidenceScope[],
) {
  const config = remoteArchiveRuntimeConfiguration.parse(configuration);
  const documentBytes = await secretFile(config.signedProfileFile, 300000);
  let privateKey: Buffer | undefined,
    commitKey: Buffer | undefined,
    authority: RemoteArchiveAuthority | undefined;
  try {
    const document = signedArchiveProfile.parse(JSON.parse(documentBytes.toString('utf8')));
    privateKey = await secretFile(config.receiptPrivateKeyFile, 4096);
    commitKey = await secretFile(config.commitKeyFile, 32, 32);
    authority = new RemoteArchiveAuthority(config.trust, document, privateKey, commitKey);
    const selected = scopes.filter(
      (s) =>
        s.participantId === config.trust.participantId &&
        s.privacyDomainId === config.trust.privacyDomainId &&
        authority!.claims.streamIds.includes(s.streamId),
    );
    if (selected.length !== authority.claims.streamIds.length)
      throw new RemoteArchiveError('INVALID');
    const credentials = async (): Promise<S3ArchiveCredentials> => {
      const bytes = await secretFile(config.credentialsFile, 16384);
      try {
        return s3ArchiveCredentials.parse(JSON.parse(bytes.toString('utf8')));
      } finally {
        bytes.fill(0);
      }
    };
    // Validate actual mounted credentials at startup without remote I/O. The
    // transport re-parses every acquisition and supports file-based renewal.
    await credentials();
    const signer = authority;
    return {
      sinkId: document.transport.sinkId,
      scopes: selected,
      sourceKind: signer.sourceKind,
      reader:
        signer.sourceKind === 'SEGMENT'
          ? new RemoteArchiveEvidenceReader(pool, signer, credentials)
          : null,
      forScope(scope: EvidenceScope) {
        signer.assertScope(scope);
        const Custody =
          signer.sourceKind === 'SEGMENT' ? RemoteArchiveCustody : ProtectedRemoteArchiveCustody;
        return new Custody(
          new PostgresRemoteArchiveAttemptOwner(pool, scope, signer),
          signer,
          credentials,
        );
      },
      close() {
        signer.close();
      },
    };
  } catch (error) {
    authority?.close();
    throw error;
  } finally {
    privateKey?.fill(0);
    commitKey?.fill(0);
    documentBytes.fill(0);
  }
}
