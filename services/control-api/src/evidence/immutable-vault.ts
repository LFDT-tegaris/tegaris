import { constants } from 'node:fs';
import { lstat, mkdir, open, link, unlink, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { EvidenceCustodyError } from './segment.js';

const hasCode = (error: unknown, code: string) =>
  error instanceof Error && 'code' in error && error.code === code;

/** Shared filesystem durability only. Each material owner validates its exact
 * version, content and privacy contract before and after these operations. */
export async function openVaultDirectory(directory: string) {
  if (!isAbsolute(directory)) throw new EvidenceCustodyError('INVALID');
  try {
    try {
      await mkdir(directory, { mode: 0o700 });
      const parent = await open(dirname(directory), constants.O_RDONLY | constants.O_DIRECTORY);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      if (!hasCode(error, 'EEXIST')) throw error;
    }
    const metadata = await lstat(directory);
    if (
      !metadata.isDirectory() ||
      (metadata.mode & 0o077) !== 0 ||
      (await realpath(directory)) !== directory
    )
      throw new EvidenceCustodyError('UNAVAILABLE');
    return directory;
  } catch {
    throw new EvidenceCustodyError('UNAVAILABLE');
  }
}

function path(directory: string, name: string) {
  if (!/^[a-z0-9.-]{1,128}$/u.test(name) || name.startsWith('.'))
    throw new EvidenceCustodyError('INVALID');
  return join(directory, name);
}

export async function readVaultFile(directory: string, name: string, maximumBytes: number) {
  let file;
  try {
    file = await open(path(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await file.stat();
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0 || metadata.size > maximumBytes)
      throw new EvidenceCustodyError('INTEGRITY');
    const bytes = await file.readFile();
    if (bytes.length > maximumBytes) throw new EvidenceCustodyError('INTEGRITY');
    return bytes;
  } catch (error) {
    if (error instanceof EvidenceCustodyError) throw error;
    throw new EvidenceCustodyError(hasCode(error, 'ENOENT') ? 'UNAVAILABLE' : 'INTEGRITY');
  } finally {
    await file?.close();
  }
}

export async function syncVaultDirectory(directory: string) {
  const handle = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Never replaces a version. Even on EEXIST the caller must independently read
 * back and validate the stored object before issuing a durability receipt. */
export async function putVaultFile(directory: string, name: string, bytes: Buffer) {
  const destination = path(directory, name);
  const temporary = join(directory, `.pending-${randomUUID()}`);
  let file;
  try {
    file = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await file.writeFile(bytes);
    await file.sync();
    await file.close();
    file = undefined;
    try {
      await link(temporary, destination);
    } catch (error) {
      if (!hasCode(error, 'EEXIST')) throw error;
    }
    await unlink(temporary);
    await syncVaultDirectory(directory);
  } catch (error) {
    if (error instanceof EvidenceCustodyError) throw error;
    throw new EvidenceCustodyError('UNAVAILABLE');
  } finally {
    await file?.close();
    await unlink(temporary).catch((error: unknown) => {
      if (!hasCode(error, 'ENOENT')) throw new EvidenceCustodyError('UNAVAILABLE');
    });
  }
}
