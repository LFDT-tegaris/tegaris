import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';

export async function writeValidatedJsonAtomically(destination, value, options = {}) {
  const resolvedDestination = resolve(destination);
  const directory = dirname(resolvedDestination);
  const temporaryPath = resolve(
    directory,
    `.${basename(resolvedDestination)}.tmp-${process.pid}-${randomUUID()}`,
  );
  const serialized = `${JSON.stringify(value, null, 2)}\n`;

  await mkdir(directory, { recursive: true });
  try {
    await writeFile(temporaryPath, serialized, { encoding: 'utf8', flag: 'wx' });
    JSON.parse(await readFile(temporaryPath, 'utf8'));
    await options.beforeRename?.();
    await rename(temporaryPath, resolvedDestination);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}
