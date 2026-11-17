import { timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  statfsSync,
  writeSync,
} from 'node:fs';
import { basename, isAbsolute, resolve } from 'node:path';
import { bindTestFactCandidateDatabaseReference } from './installation-consumer-bindings.mjs';
import { InstallationConfigError } from './installation-config-inputs.mjs';

const TMPFS_MAGIC = 0x01021994n;
const CLAIM = '.test-fact-secret-owner';
const CODE = 'OPS_TEST_FACT_SECRET_MOUNT_INVALID';
const errorReasons = new WeakMap();
function failure(reason) {
  const error = new InstallationConfigError(reason, CODE);
  errorReasons.set(error, reason);
  return error;
}
const fail = (reason) => {
  throw failure(reason);
};
const safeError = (error, reason) => failure(errorReasons.get(error) ?? reason);
const identity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const mode = (stat) => Number(stat.mode & 0o7777n);
const owned = (stat, binding) =>
  stat.uid === BigInt(binding.workloadUid) && stat.gid === BigInt(binding.workloadGid);

function readBounded(fd, length) {
  const bytes = Buffer.alloc(length + 1);
  let offset = 0;
  try {
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== length) fail('FILE_CHANGED');
    return bytes;
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (count === 0) fail('PUBLICATION_FAILED');
    offset += count;
  }
}

/**
 * One immutable publication root, supplied empty by the runtime owner on real
 * Linux tmpfs. Run as UID/GID 65532. The owner must exclusively reserve this
 * directory and its namespace; hostile same-UID processes/root are not isolated
 * by Unix permissions. A pinned directory descriptor prevents path substitution
 * from redirecting writes to another directory or a disk-backed filesystem.
 *
 * Call publish(existingTestProvider) ONLY inside the integrator's authenticated
 * recipient-delivery operation. The real provider validates the exact binding
 * and DSN and lends bytes through withMaterial; this module does not authenticate
 * a provider object, caller, workload, mount or readiness. Never accept such an
 * object from a network request. No raw material parameter is exposed here.
 *
 * Mount this root's candidate-url at the committed read-only consumer path only
 * AFTER publish resolves. Repeats verify the original inode and bytes; a changed
 * value/version requires a NEW root and owner-controlled consumer replacement.
 * dispose erases the retained inode and closes descriptors, leaving inert names
 * for the runtime owner's tmpfs teardown. There is deliberately no path unlink,
 * takeover/reopen, automatic remount, or claim about open files/DB sessions.
 * An interrupted or uncertain root cannot be reused; teardown stays with its
 * original runtime owner. No filesystem adapter or fallback bypasses tmpfs checks.
 */
export function createTestFactSecretMount(rootPath, reference, version) {
  let binding;
  try {
    binding = bindTestFactCandidateDatabaseReference(reference, version);
  } catch {
    fail('BINDING_INVALID');
  }
  if (
    typeof rootPath !== 'string' ||
    rootPath.length > 4096 ||
    !isAbsolute(rootPath) ||
    resolve(rootPath) !== rootPath ||
    [...rootPath].some(
      (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    fail('ROOT_PATH_INVALID');
  if (
    process.platform !== 'linux' ||
    process.geteuid?.() !== binding.workloadUid ||
    process.getegid?.() !== binding.workloadGid
  )
    fail('EXECUTION_IDENTITY');

  let rootFd;
  let claimFd;
  let fileFd;
  let rootIdentity;
  let claimIdentity;
  let fileIdentity;
  let expected;
  let sealed = false;
  let closed = false;
  let terminalFailure;
  let busy = false;
  const name = basename(binding.mountPath);
  const anchor = () => `/proc/self/fd/${rootFd}`;
  const path = (entry) => `${anchor()}/${entry}`;

  function verifyRoot() {
    const current = fstatSync(rootFd, { bigint: true });
    const named = lstatSync(rootPath, { bigint: true });
    if (
      !current.isDirectory() ||
      !named.isDirectory() ||
      !identity(current, rootIdentity) ||
      !identity(current, named) ||
      !owned(current, binding) ||
      mode(current) !== 0o700 ||
      realpathSync(rootPath) !== rootPath
    )
      fail('ROOT_CHANGED');
    if (statfsSync(anchor(), { bigint: true }).type !== TMPFS_MAGIC) fail('BACKING_INVALID');
  }

  function verifyNamespace() {
    verifyRoot();
    const claim = fstatSync(claimFd, { bigint: true });
    const named = lstatSync(path(CLAIM), { bigint: true });
    if (
      !claim.isFile() ||
      !named.isFile() ||
      !identity(claim, claimIdentity) ||
      !identity(claim, named) ||
      claim.dev !== rootIdentity.dev ||
      !owned(claim, binding) ||
      mode(claim) !== 0 ||
      claim.nlink !== 1n ||
      claim.size !== 0n
    )
      fail('OWNERSHIP_CHANGED');
    const entries = readdirSync(anchor()).sort();
    const allowed = (fileFd === undefined ? [CLAIM] : [CLAIM, name]).sort();
    if (entries.length !== allowed.length || entries.some((entry, i) => entry !== allowed[i]))
      fail('ROOT_CONTENTS_CHANGED');
  }

  function verifyFile(partial = false) {
    verifyNamespace();
    const stat = fstatSync(fileFd, { bigint: true });
    const named = lstatSync(path(name), { bigint: true });
    if (
      !stat.isFile() ||
      !named.isFile() ||
      !identity(stat, fileIdentity) ||
      !identity(stat, named) ||
      stat.dev !== rootIdentity.dev ||
      !owned(stat, binding) ||
      stat.nlink !== 1n ||
      mode(stat) !== (sealed ? 0o400 : 0) ||
      stat.size > BigInt(expected.length) ||
      (!partial && stat.size !== BigInt(expected.length))
    )
      fail('FILE_CHANGED');
    const length = Number(stat.size);
    const bytes = readBounded(fileFd, length);
    try {
      if (!timingSafeEqual(bytes.subarray(0, length), expected.subarray(0, length)))
        fail('FILE_CHANGED');
      const after = fstatSync(fileFd, { bigint: true });
      if (
        !identity(stat, after) ||
        stat.ctimeNs !== after.ctimeNs ||
        stat.mtimeNs !== after.mtimeNs ||
        stat.size !== after.size ||
        stat.nlink !== after.nlink ||
        stat.mode !== after.mode
      )
        fail('FILE_CHANGED');
      return length;
    } finally {
      bytes.fill(0);
    }
  }

  function eraseFile() {
    if (fileFd === undefined) return;
    const length = verifyFile(!sealed);
    const zeroes = Buffer.alloc(length);
    try {
      // Address only our retained descriptor; never open/truncate by pathname.
      fchmodSync(fileFd, 0);
      writeAll(fileFd, zeroes);
      ftruncateSync(fileFd, 0);
      fsyncSync(fileFd);
    } finally {
      zeroes.fill(0);
    }
  }

  function finish() {
    let failure;
    try {
      verifyNamespace();
      eraseFile();
    } catch (error) {
      failure = safeError(error, 'CLEANUP_UNCERTAIN');
    } finally {
      expected?.fill(0);
      expected = undefined;
      for (const fd of [fileFd, claimFd, rootFd]) {
        if (fd === undefined) continue;
        try {
          closeSync(fd);
        } catch {
          failure ??= safeError(undefined, 'CLEANUP_UNCERTAIN');
        }
      }
      closed = true;
      terminalFailure = failure;
    }
    if (failure) throw failure;
  }

  try {
    rootFd = openSync(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    rootIdentity = fstatSync(rootFd, { bigint: true });
    verifyRoot();
    if (readdirSync(anchor()).length !== 0) fail('ROOT_NOT_EMPTY');
    claimFd = openSync(
      path(CLAIM),
      constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0,
    );
    claimIdentity = fstatSync(claimFd, { bigint: true });
    verifyNamespace();
  } catch (error) {
    for (const fd of [claimFd, rootFd]) {
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          // The claimed namespace is never silently reused or removed.
        }
      }
    }
    throw safeError(error, 'ROOT_UNAVAILABLE');
  }

  return Object.freeze({
    async publish(provider) {
      if (closed) fail('PUBLICATION_CLOSED');
      if (busy) fail('PUBLICATION_BUSY');
      busy = true;
      const previouslyPublished = sealed;
      let received = false;
      let handoffOpen = true;
      let localFailure;
      try {
        verifyNamespace();
        await provider.withMaterial(binding, (input) => {
          let bytes;
          try {
            if (!handoffOpen || closed) fail('HANDOFF_CLOSED');
            if (received) fail('HANDOFF_REPEATED');
            received = true;
            if (!(input instanceof Uint8Array) || input.byteLength === 0 || input.byteLength > 4096)
              fail('MATERIAL_INVALID');
            bytes = Buffer.from(input);
            verifyNamespace();
            if (sealed) {
              verifyFile();
              if (bytes.length !== expected.length || !timingSafeEqual(bytes, expected))
                fail('MATERIAL_CHANGED');
              return;
            }
            fileFd = openSync(
              path(name),
              constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
              0,
            );
            fileIdentity = fstatSync(fileFd, { bigint: true });
            expected = bytes;
            bytes = undefined;
            verifyFile(true);
            writeAll(fileFd, expected);
            fsyncSync(fileFd);
            verifyFile();
            fchmodSync(fileFd, 0o400);
            sealed = true;
            verifyFile();
          } catch (error) {
            localFailure = safeError(error, 'PUBLICATION_FAILED');
            throw localFailure;
          } finally {
            bytes?.fill(0);
          }
        });
        if (localFailure) throw localFailure;
        if (!received || !sealed) fail('HANDOFF_MISSING');
        verifyFile();
      } catch (error) {
        const failure = safeError(localFailure ?? error, 'PROVIDER_REJECTED');
        if (!previouslyPublished && fileFd !== undefined) {
          // A rejected initial handoff must not leave a usable publication.
          try {
            finish();
          } catch (cleanupError) {
            // Retain the first rejection and expose only a fixed cleanup reason.
            failure.cleanupReason = safeError(cleanupError, 'CLEANUP_UNCERTAIN').reason;
          }
        }
        throw failure;
      } finally {
        handoffOpen = false;
        busy = false;
      }
    },
    dispose() {
      if (closed) {
        if (terminalFailure) throw safeError(terminalFailure, 'CLEANUP_UNCERTAIN');
        return;
      }
      if (busy) fail('PUBLICATION_BUSY');
      finish();
    },
  });
}
