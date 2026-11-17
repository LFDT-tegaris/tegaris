import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, rm, rmdir, unlink } from 'node:fs/promises';
import path from 'node:path';

import { withModuleFile } from './module-file-io.mjs';

const lockName = '.openpc-module-generation.lock';

function targetPath(root, destination) {
  const relative = path.relative(root, destination);
  if (
    !relative ||
    relative.split(path.sep).some((part) => ['', '.', '..'].includes(part)) ||
    path.isAbsolute(relative) ||
    !(
      relative.startsWith(`policies${path.sep}modules${path.sep}generated${path.sep}`) ||
      [
        'services/module-registry/src/generated/contracts.ts',
        'crates/pc-module-sdk/src/generated.rs',
        'crates/pc-policy-core/src/generated.rs',
        'tests/conformance/modules/generated-source-index.json',
      ].some((name) => relative === name.split('/').join(path.sep))
    )
  )
    throw new Error('Module generation output leaves its managed paths');
  return path.join(root, relative);
}

async function existingFile(file) {
  if (typeof constants.O_NOFOLLOW !== 'number' || typeof constants.O_NONBLOCK !== 'number')
    throw new Error('Module generation requires no-follow file validation');
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  return withModuleFile(handle, async () => {
    const status = await handle.stat();
    if (!status.isFile() || status.size > 64 * 1024 * 1024)
      throw new Error('Module generation target is not a bounded regular file');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      status.size !== bytes.length ||
      status.size !== after.size ||
      status.mtimeMs !== after.mtimeMs
    )
      throw new Error('Module generation target changed during read');
    return { bytes, mode: status.mode & 0o777 };
  });
}

async function parents(root, destination, create, created) {
  const parts = path.relative(root, path.dirname(destination)).split(path.sep);
  let current = root;
  for (const part of ['', ...parts]) {
    if (part) current = path.join(current, part);
    let status;
    try {
      status = await lstat(current);
    } catch (error) {
      if (error.code !== 'ENOENT' || !create) throw error;
      await mkdir(current, { mode: 0o755 });
      created.push(current);
      status = await lstat(current);
    }
    if (!status.isDirectory() || status.isSymbolicLink())
      throw new Error('Module generation output parent is not a regular directory');
  }
}

const sameFile = (left, right) =>
  left === null || right === null
    ? left === right
    : left.mode === right.mode && left.bytes.equals(right.bytes);

async function stageFile(file, bytes, mode) {
  const handle = await open(file, 'wx', 0o600);
  return withModuleFile(handle, async () => {
    await handle.writeFile(bytes);
    await handle.chmod(mode);
    await handle.sync();
  });
}

async function validateGeneratedInventory(root, entries) {
  const generated = path.join(root, 'policies/modules/generated');
  const allowed = new Set(entries.map((entry) => entry.destination));
  // Historical verification does not emit the separate public provenance record.
  allowed.add(path.join(generated, 'public-source-provenance.json'));
  async function visit(directory) {
    let status;
    try {
      status = await lstat(directory);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    if (!status.isDirectory() || status.isSymbolicLink())
      throw new Error('Module generation output parent is not a regular directory');
    for (const name of await readdir(directory)) {
      const file = path.join(directory, name);
      const item = await lstat(file);
      if (item.isDirectory() && !item.isSymbolicLink()) await visit(file);
      else if (!item.isFile() || item.isSymbolicLink() || !allowed.has(file))
        throw new Error(`Unexpected generated output: ${path.relative(root, file)}`);
    }
  }
  await visit(generated);
}

/** Single writer, staged inputs and whole-set rollback. This is not a
 * crash-atomic filesystem transaction or a lock for external build readers. */
export async function publishModuleOutputs(repositoryRoot, outputs, { checkOnly }) {
  const root = path.resolve(repositoryRoot);
  const lock = path.join(root, lockName);
  const entries = [...outputs].map(([destination, bytes]) => ({
    destination: targetPath(root, destination),
    bytes,
  }));
  if (entries.some((entry) => !Buffer.isBuffer(entry.bytes)))
    throw new Error('Module generation requires complete buffered outputs');
  if (checkOnly) {
    try {
      await lstat(lock);
      throw new Error('A module generation lock exists; reconcile its owner before checking');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await validateGeneratedInventory(root, entries);
    for (const entry of entries) {
      await parents(root, entry.destination, false, []);
      const existing = await existingFile(entry.destination);
      if (!existing || !existing.bytes.equals(entry.bytes))
        throw new Error(`Generated output drift: ${path.relative(root, entry.destination)}`);
    }
    return;
  }
  await mkdir(lock, { mode: 0o700 });
  const ownedLock = await lstat(lock);
  const created = [];
  const replaced = [];
  let retainLock = false;
  let primaryFailure;
  async function replaceOutputs() {
    try {
      await validateGeneratedInventory(root, entries);
      for (let index = 0; index < entries.length; index++) {
        const entry = entries[index];
        await parents(root, entry.destination, true, created);
        entry.before = await existingFile(entry.destination);
        entry.mode = entry.before?.mode ?? 0o644;
        if (entry.before?.bytes.equals(entry.bytes)) continue;
        entry.staged = path.join(lock, `${index}.new`);
        entry.backup = path.join(lock, `${index}.previous`);
        await stageFile(entry.staged, entry.bytes, entry.mode);
        if (entry.before) await stageFile(entry.backup, entry.before.bytes, entry.before.mode);
      }
      for (const entry of entries) {
        if (!entry.staged) continue;
        await parents(root, entry.destination, false, []);
        if (!sameFile(await existingFile(entry.destination), entry.before))
          throw new Error('Module generation output changed before replacement');
        await rename(entry.staged, entry.destination);
        replaced.push(entry);
      }
    } catch (failure) {
      const recoveryErrors = [];
      for (const entry of replaced.reverse()) {
        try {
          await parents(root, entry.destination, false, []);
          const current = await existingFile(entry.destination);
          if (!current || current.mode !== entry.mode || !current.bytes.equals(entry.bytes))
            throw new Error('Module generation cannot overwrite a concurrently changed output');
          if (entry.before) await rename(entry.backup, entry.destination);
          else await unlink(entry.destination);
        } catch (error) {
          recoveryErrors.push(error);
        }
      }
      if (recoveryErrors.length) {
        retainLock = true;
        throw new AggregateError(
          [failure, ...recoveryErrors],
          'Module generation failed; original backups are retained in its lock directory',
        );
      }
      for (const directory of created.reverse()) {
        try {
          await rmdir(directory);
        } catch (error) {
          if (!['ENOTEMPTY', 'ENOENT'].includes(error.code)) {
            retainLock = true;
            throw new AggregateError([failure, error], 'Module generation cleanup failed');
          }
        }
      }
      throw failure;
    }
  }
  try {
    await replaceOutputs();
  } catch (failure) {
    primaryFailure = failure;
  }
  if (!retainLock) {
    try {
      const current = await lstat(lock);
      if (!current.isDirectory() || current.ino !== ownedLock.ino || current.dev !== ownedLock.dev)
        throw new Error('Module generation lock changed; automatic cleanup stopped');
      await rm(lock, { recursive: true });
    } catch (cleanupFailure) {
      if (primaryFailure)
        throw new AggregateError(
          [primaryFailure, cleanupFailure],
          'Module generation cleanup failed',
        );
      throw cleanupFailure;
    }
  }
  if (primaryFailure) throw primaryFailure;
}
