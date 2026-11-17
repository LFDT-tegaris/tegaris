import {
  bindTestFactCandidateDatabaseReference,
  testFactCandidateDatabaseConsumer,
} from './installation-consumer-bindings.mjs';
import { constants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rmdir,
  unlink,
} from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { InstallationConfigError, invalid } from './installation-config-inputs.mjs';
import { prepareInstallationCandidate } from './installation-config-validation.mjs';

/** Candidate files are deliberately not process configuration or launch instructions. */
export function renderInstallationCandidate(sources, options) {
  const candidate = prepareInstallationCandidate(sources, options);
  const consumerBindings =
    candidate.configuration.profile === 'test'
      ? candidate.secretReferences
          .filter(({ field }) => field === testFactCandidateDatabaseConsumer.field)
          .map(({ reference, version }) =>
            bindTestFactCandidateDatabaseReference(reference, version),
          )
      : [];
  const mountPlan = {
    state: candidate.state,
    startupAllowed: false,
    blockers: candidate.blockers,
    candidateDigest: candidate.candidateDigest,
    inputDigests: candidate.inputDigests,
    generation: candidate.configuration.generation,
    // Consumer paths/roles must come from actual entrypoints, not caller-supplied names.
    consumerBindings,
    unresolvedSecretMounts: candidate.secretReferences.map(({ field, reference, version }) => ({
      field,
      reference,
      version,
      readOnly: true,
      consumer: null,
      mountPath: null,
    })),
  };
  const files = {
    'configuration.candidate.json': `${canonicalJson(candidate)}\n`,
    'mount-plan.candidate.json': `${canonicalJson(mountPlan)}\n`,
  };
  return {
    files,
    directoryName: `candidate-${sha256(files).slice(7)}`,
    // Safe for normal diagnostics: no source values, secret names, or reference fingerprints.
    summary: { state: 'BLOCKED', startupAllowed: false, blockers: candidate.blockers },
  };
}

async function assertPrivateDirectory(path) {
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    (stat.mode & 0o077) !== 0 ||
    (await realpath(path)) !== resolve(path)
  )
    invalid('OUTPUT_DIRECTORY_UNSAFE');
}

async function verifyExisting(directory, files) {
  await assertPrivateDirectory(directory);
  if (((await lstat(directory)).mode & 0o777) !== 0o500) invalid('MATERIALIZATION_CONFLICT');
  if (canonicalJson((await readdir(directory)).sort()) !== canonicalJson(Object.keys(files).sort()))
    invalid('MATERIALIZATION_CONFLICT');
  for (const [name, contents] of Object.entries(files)) {
    let file;
    try {
      file = await open(
        join(directory, name),
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      const stat = await file.stat();
      if (
        !stat.isFile() ||
        stat.uid !== process.getuid() ||
        stat.nlink !== 1 ||
        (stat.mode & 0o777) !== 0o400 ||
        stat.size !== Buffer.byteLength(contents)
      )
        invalid('MATERIALIZATION_CONFLICT');
      const bytes = Buffer.alloc(stat.size + 1);
      let length = 0;
      while (length < bytes.length) {
        const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
        if (bytesRead === 0) break;
        length += bytesRead;
      }
      if (length !== stat.size || !bytes.subarray(0, length).equals(Buffer.from(contents)))
        invalid('MATERIALIZATION_CONFLICT');
    } finally {
      await file?.close();
    }
  }
}

/**
 * Write an immutable private candidate directory; never overwrite a live read-only mount.
 * A changed candidate gets a new directory. The installer owns consumer replacement/restart.
 * The caller must provide an existing exclusively owned private directory, not a live volume.
 */
export async function materializeInstallationCandidate(sources, { outputRoot, ...options }) {
  const rendered = renderInstallationCandidate(sources, options);
  if (typeof outputRoot !== 'string' || !isAbsolute(outputRoot) || outputRoot.length > 4096)
    invalid('OUTPUT_PATH');
  let stage;
  let failure;
  const created = [];
  try {
    await assertPrivateDirectory(outputRoot);
    const destination = join(outputRoot, rendered.directoryName);
    try {
      await lstat(destination);
      await verifyExisting(destination, rendered.files);
      return { ...rendered.summary, directory: destination, reused: true };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    stage = await mkdtemp(join(outputRoot, '.installation-'));
    await chmod(stage, 0o700);
    for (const [name, contents] of Object.entries(rendered.files)) {
      const path = join(stage, name);
      const file = await open(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o600,
      );
      created.push(path);
      try {
        await file.writeFile(contents);
        await file.chmod(0o400);
        await file.sync();
      } finally {
        await file.close();
      }
    }
    // Serialize publishers under this exclusively owned output root. Never replace an existing
    // directory through rename: a repeat verifies it, and an interrupted owner fails closed.
    const publicationLock = join(outputRoot, '.installation-publish');
    try {
      await mkdir(publicationLock, { mode: 0o700 });
    } catch {
      invalid('MATERIALIZATION_BUSY');
    }
    let reused = false;
    try {
      try {
        await lstat(destination);
        reused = true;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      if (reused) await verifyExisting(destination, rendered.files);
      else {
        await chmod(stage, 0o500);
        const stagedDirectory = await open(
          stage,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        try {
          await stagedDirectory.sync();
        } finally {
          await stagedDirectory.close();
        }
        await rename(stage, destination);
        stage = undefined;
        const directory = await open(
          outputRoot,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        try {
          await directory.sync();
        } finally {
          await directory.close();
        }
      }
    } finally {
      await rmdir(publicationLock);
    }
    return { ...rendered.summary, directory: destination, reused };
  } catch (error) {
    failure =
      error instanceof InstallationConfigError
        ? error
        : new InstallationConfigError('MATERIALIZATION_UNAVAILABLE');
    throw failure;
  } finally {
    if (stage) {
      // Only names this invocation created; never recurse or clean another candidate/lock.
      try {
        await chmod(stage, 0o700);
        for (const path of created) await unlink(path);
        await rmdir(stage);
      } catch {
        if (failure) failure.cleanupFailed = true;
        else invalid('MATERIALIZATION_CLEANUP_FAILED');
      }
    }
  }
}
