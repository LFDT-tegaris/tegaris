import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { CliError } from './client.js';

export async function readJson(
  path: string,
  protectedFile: boolean,
  maximumBytes = 16_384,
): Promise<unknown> {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.size > maximumBytes ||
      (protectedFile &&
        ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.() || stat.nlink !== 1))
    )
      throw new CliError('INPUT');
    const bytes = Buffer.alloc(maximumBytes + 1);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead > maximumBytes) throw new CliError('INPUT');
    return JSON.parse(bytes.subarray(0, bytesRead).toString('utf8'));
  } catch {
    throw new CliError(protectedFile ? 'AUTHENTICATION' : 'INPUT');
  } finally {
    await file?.close();
  }
}

export async function privateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o077) !== 0
  )
    throw new CliError('AUTHENTICATION');
}

/** Atomically retain replay information before dispatch, never a success claim. */
export async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await privateDirectory(dirname(path));
  const temporary = `${path}.${randomUUID()}.tmp`;
  const file = await open(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(JSON.stringify(value));
    await file.sync();
    await file.close();
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } finally {
    await file.close().catch(() => undefined);
    await rm(temporary, { force: true });
  }
}
