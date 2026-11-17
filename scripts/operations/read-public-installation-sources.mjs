import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import {
  authenticateOperationsSources,
  publicOperationsSourceAnchor,
  publicOperationsSourceProfiles,
} from './installation-source-authentication.mjs';

const fail = () => {
  throw new InstallationConfigError('C17_SOURCE_AUTHENTICATION_FAILED');
};
async function fixedBytes(root, path, expectedSize) {
  const file = await open(
    join(root, path),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size !== expectedSize) fail();
    const result = Buffer.alloc(expectedSize + 1);
    let size = 0;
    while (size < result.length) {
      const read = await file.read(result, size, result.length - size, null);
      if (read.bytesRead === 0) break;
      size += read.bytesRead;
    }
    if (size !== expectedSize) fail();
    return result.subarray(0, size);
  } finally {
    await file.close();
  }
}
/** Reads and authenticates all six published inputs before selecting a profile.
 * There is no private-package lookup or failed-source fallback. */
export async function readPublicOperationsSources(input) {
  try {
    if (!input || Object.getPrototypeOf(input) !== Object.prototype) fail();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = [
      'sourceProfile',
      'profile',
      ...(Object.hasOwn(descriptors, 'root') ? ['root'] : []),
    ];
    if (
      Reflect.ownKeys(descriptors).length !== keys.length ||
      keys.some((key) => !descriptors[key]?.enumerable || !Object.hasOwn(descriptors[key], 'value'))
    )
      fail();
    if (
      input.sourceProfile !== publicOperationsSourceAnchor.sourceProfile ||
      typeof input.profile !== 'string' ||
      !Object.hasOwn(publicOperationsSourceProfiles, input.profile)
    )
      fail();
    if (input.root !== undefined && (typeof input.root !== 'string' || !input.root.startsWith('/')))
      fail();
    const root = await realpath(input.root ?? fileURLToPath(new URL('../../', import.meta.url)));
    const inventoryBytes = await fixedBytes(
      root,
      'config/source-authentication/public-operations-source-v1.json',
      publicOperationsSourceAnchor.inventoryBytes,
    );
    const schemaBytes = await fixedBytes(
      root,
      publicOperationsSourceAnchor.schemaPath,
      publicOperationsSourceAnchor.schemaBytes,
    );
    let selected;
    for (const [profile, entry] of Object.entries(publicOperationsSourceProfiles)) {
      const profileBytes = await fixedBytes(root, entry.path, entry.bytes);
      const authenticated = authenticateOperationsSources({
        sourceProfile: input.sourceProfile,
        inventoryBytes,
        schemaBytes,
        profileBytes,
        profile,
      });
      if (profile === input.profile) selected = authenticated;
    }
    if (!selected) fail();
    return selected;
  } catch {
    fail();
  }
}
