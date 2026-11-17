import { open, opendir, readlink, stat } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { canonicalJson } from '../../services/control-api/src/configuration/digest.ts';

const uint = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => /^[0-9]+$/u.test(v) && BigInt(v) <= 18446744073709551615n);
export const installationProcessIdentitySchema = z.strictObject({
  pid: z.number().int().positive(),
  startTicks: uint,
  bootId: z.uuid(),
  startedAtMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  executable: z.string(),
  uid: z.number().int().nonnegative(),
});
const namespace = z.string().regex(/^(mnt|pid|net|ipc|uts|user|cgroup):\[[1-9][0-9]*\]$/u);
const ceiling = z.union([uint, z.literal('max')]);
export const installationProcessIsolationSchema = z.strictObject({
  process: installationProcessIdentitySchema,
  namespaces: z.strictObject({
    mnt: namespace,
    pid: namespace,
    net: namespace,
    ipc: namespace,
    uts: namespace,
    user: namespace,
    cgroup: namespace,
  }),
  cgroup: z.string().min(1).max(8192),
  executableDevice: uint,
  executableInode: uint,
  security: z.strictObject({
    noNewPrivileges: z.number().int().min(0).max(1),
    seccomp: z.number().int().min(0).max(2),
    capabilities: z.array(z.string().regex(/^[0-9a-f]{16}$/u)).length(5),
    rootMountId: uint,
    rootDevice: z.string().regex(/^[0-9]+:[0-9]+$/u),
    rootReadOnly: z.boolean(),
  }),
  limits: z.strictObject({
    memoryBytes: ceiling.nullable(),
    cpuQuota: ceiling.nullable(),
    cpuPeriod: uint.nullable(),
    pids: ceiling.nullable(),
  }),
});
export class InstallationProcessObservationError extends Error {
  constructor(cause) {
    super('INSTALLATION_PROCESS_OBSERVATION_UNKNOWN', { cause });
  }
}
function fail() {
  throw new InstallationProcessObservationError();
}

const observationBudgets = new AsyncLocalStorage();
const caps = Object.freeze({
  processStat: 8192,
  status: 65536,
  bootId: 128,
  bootStat: 1048576,
  cgroup: 8192,
  mountinfo: 1048576,
  controller: 128,
});
function assertBudget(budget) {
  if (budget.controller.signal.aborted || performance.now() >= budget.deadline) fail();
}
function owned(budget, operation) {
  assertBudget(budget);
  const pending = Promise.resolve().then(() => {
    assertBudget(budget);
    return operation();
  });
  budget.pending.add(pending);
  void pending.then(
    () => budget.pending.delete(pending),
    () => budget.pending.delete(pending),
  );
  return pending;
}
/** Resource scope only, never observation/authority. Nested process observations
 * inherit ONE private30s monotonic budget. Native collectors can wrap their whole
 * bracket with this function without changing original pins or return bytes.
 * FileHandle.read/readlink/stat cannot be canceled portably; all owned calls and
 * FD cleanup must finish before return. Late completion denies. This is NOT a
 * hard wall-time guarantee for an uninterruptible kernel operation. */
export async function withInstallationProcessObservationBudget(operation) {
  if (typeof operation !== 'function') fail();
  const inherited = observationBudgets.getStore();
  if (inherited) {
    assertBudget(inherited);
    const result = await operation();
    assertBudget(inherited);
    return result;
  }
  const budget = {
    deadline: performance.now() + 30000,
    controller: new AbortController(),
    pending: new Set(),
  };
  const timer = setTimeout(() => budget.controller.abort(), 30000);
  timer.unref();
  return observationBudgets.run(budget, async () => {
    let result,
      failure,
      failed = false;
    try {
      result = await operation();
      if (budget.pending.size !== 0) fail();
      assertBudget(budget);
    } catch (error) {
      failure = error;
      failed = true;
    } finally {
      budget.controller.abort();
      // Do not return while OUR parallel IO/FD cleanup remains pending, even on
      // a failed sibling. No uncancellable pending operation becomes success.
      const remaining = await Promise.allSettled([...budget.pending]);
      clearTimeout(timer);
      const cleanup = remaining
        .filter((item) => item.status === 'rejected')
        .map((item) => item.reason);
      if (cleanup.length) {
        failure = new InstallationProcessObservationError(
          new AggregateError([...(failed ? [failure] : []), ...cleanup]),
        );
        failed = true;
      }
    }
    if (failed) throw failure;
    return result;
  });
}
function budget() {
  const value = observationBudgets.getStore();
  if (!value) fail();
  assertBudget(value);
  return value;
}
async function boundedRead(path, ceiling) {
  const current = budget();
  return owned(current, async () => {
    const bytes = Buffer.alloc(ceiling + 1);
    let handle,
      failure,
      result,
      failed = false;
    try {
      assertBudget(current);
      handle = await open(path, 'r');
      let offset = 0;
      while (true) {
        assertBudget(current);
        const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, null);
        assertBudget(current);
        if (!Number.isSafeInteger(bytesRead) || bytesRead < 0 || bytesRead > bytes.length - offset)
          fail();
        offset += bytesRead;
        if (offset > ceiling) fail();
        if (bytesRead === 0) {
          result = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset));
          break;
        }
      }
    } catch (error) {
      failure = error;
      failed = true;
    } finally {
      bytes.fill(0);
      if (handle) {
        try {
          await handle.close();
        } catch (error) {
          failure = new InstallationProcessObservationError(
            new AggregateError([...(failed ? [failure] : []), error]),
          );
          failed = true;
        }
      }
    }
    if (failed) throw failure;
    assertBudget(current);
    return result;
  });
}
async function boundedLink(path) {
  const current = budget();
  return owned(current, async () => {
    const value = await readlink(path);
    assertBudget(current);
    if (typeof value !== 'string' || value.length > 4096 || value.includes('\0')) fail();
    return value;
  });
}
async function executableValue(override) {
  const current = budget();
  if (typeof override === 'string') return override;
  // Legacy caller-owned promises cannot be cancelled or transferred to this
  // observer. Stop awaiting them at expiry; their completion never renews us.
  return new Promise((resolve, reject) => {
    const abort = () => reject(new InstallationProcessObservationError());
    current.controller.signal.addEventListener('abort', abort, { once: true });
    const settle = (operation, value) => {
      current.controller.signal.removeEventListener('abort', abort);
      try {
        assertBudget(current);
        operation(value);
      } catch (error) {
        reject(error);
      }
    };
    try {
      Promise.prototype.then.call(
        override,
        (value) => settle(resolve, value),
        (error) => settle(reject, error),
      );
    } catch (error) {
      settle(reject, error);
    }
  });
}
async function clockTicks() {
  const current = budget();
  return owned(
    current,
    () =>
      new Promise((resolve, reject) => {
        assertBudget(current);
        let result, failure;
        const child = execFile(
          'getconf',
          ['CLK_TCK'],
          {
            timeout: Math.max(1, Math.min(2000, Math.floor(current.deadline - performance.now()))),
            maxBuffer: 256,
            signal: current.controller.signal,
            killSignal: 'SIGKILL',
          },
          (error, stdout, stderr) => {
            failure = error;
            result = { stdout, stderr };
          },
        );
        child.once('error', (error) => {
          failure = error;
        });
        // Own the child through close, including timeout/abort/output overflow.
        child.once('close', () => {
          try {
            assertBudget(current);
            if (failure) throw failure;
            if (!result || result.stderr !== '' || !/^[1-9][0-9]{0,8}\n?$/u.test(result.stdout))
              fail();
            resolve(Number(result.stdout.trim()));
          } catch (error) {
            reject(error);
          }
        });
      }),
  );
}
function validatePid(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) fail();
}
/** Bounded historical data only, never a socket/registration authority proof. */
export async function readInstallationProcessTcp4Table(pid) {
  validatePid(pid);
  return withInstallationProcessObservationBudget(() =>
    boundedRead(`/proc/${pid}/net/tcp`, 262144),
  );
}
/** Incremental fixed-path enumeration. Missing/disappearing entries or failed
 * directory cleanup deny the WHOLE observation, never partial ownership. */
export async function readInstallationProcessFileDescriptors(pid) {
  validatePid(pid);
  return withInstallationProcessObservationBudget(() => {
    const current = budget();
    return owned(current, async () => {
      let directory,
        failure,
        failed = false;
      const links = [],
        names = new Set();
      let units = 0;
      try {
        directory = await opendir(`/proc/${pid}/fd`, { bufferSize: 8 });
        while (true) {
          assertBudget(current);
          const entry = await directory.read();
          assertBudget(current);
          if (entry === null) break;
          if (
            links.length >= 1024 ||
            typeof entry.name !== 'string' ||
            !/^(0|[1-9][0-9]{0,9})$/u.test(entry.name) ||
            Number(entry.name) > 2147483647 ||
            names.has(entry.name) ||
            !entry.isSymbolicLink()
          )
            fail();
          names.add(entry.name);
          const target = await boundedLink(`/proc/${pid}/fd/${entry.name}`);
          units += entry.name.length + target.length;
          if (!target.length || units > 262144) fail();
          links.push(Object.freeze({ fd: entry.name, target }));
        }
      } catch (error) {
        failure = error;
        failed = true;
      } finally {
        if (directory) {
          try {
            await directory.close();
          } catch (error) {
            failure = new InstallationProcessObservationError(
              new AggregateError([...(failed ? [failure] : []), error]),
            );
            failed = true;
          }
        }
      }
      if (failed) throw failure;
      assertBudget(current);
      return Object.freeze(links);
    });
  });
}

/** Existing Linux process mechanics. The executable override is only for the
 * legacy FACT Docker reader, whose independently checked entrypoint is retained.
 * New isolation observations always resolve the actual procfs executable. */
export async function readInstallationProcessIdentity(pid, executableOverride) {
  validatePid(pid);
  return withInstallationProcessObservationBudget(async () => {
    const [processStat, status, executable, bootId, boot, ticks] = await Promise.all([
      boundedRead(`/proc/${pid}/stat`, caps.processStat),
      boundedRead(`/proc/${pid}/status`, caps.status),
      executableOverride === undefined
        ? boundedLink(`/proc/${pid}/exe`)
        : executableValue(executableOverride),
      boundedRead('/proc/sys/kernel/random/boot_id', caps.bootId),
      boundedRead('/proc/stat', caps.bootStat),
      clockTicks(),
    ]);
    if (
      !processStat.startsWith(`${pid} (`) ||
      !processStat.endsWith('\n') ||
      processStat.includes('\0') ||
      processStat.lastIndexOf(') ') < 0
    )
      fail();
    const fields = processStat
      .slice(processStat.lastIndexOf(')') + 2)
      .trim()
      .split(/\s+/u);
    const startTicks = fields[19],
      frequency = ticks;
    const btime = Number(/^btime ([0-9]+)$/mu.exec(boot)?.[1]);
    const uids = /^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$/mu.exec(status);
    const uid = Number(uids?.[1]);
    if (
      !startTicks ||
      !/^[1-9][0-9]*$/u.test(startTicks) ||
      !Number.isSafeInteger(frequency) ||
      frequency <= 0 ||
      !Number.isSafeInteger(btime) ||
      !Number.isSafeInteger(uid) ||
      !uids?.slice(1).every((v) => Number(v) === uid) ||
      typeof executable !== 'string' ||
      !executable.startsWith('/') ||
      executable.length > 4096 ||
      executable.includes('\0') ||
      executable.endsWith(' (deleted)')
    )
      fail();
    return installationProcessIdentitySchema.parse({
      pid,
      startTicks,
      bootId: bootId.trim(),
      executable,
      uid,
      startedAtMs: btime * 1000 + Number((BigInt(startTicks) * 1000n) / BigInt(frequency)),
    });
  });
}

/** Point-in-time host measurement, not a process lease or caller authority.
 * Missing permissions, namespaces, cgroups or stable PID identity fail closed. */
export async function readInstallationProcessIsolation(pid) {
  return withInstallationProcessObservationBudget(async () => {
    try {
      const before = await readInstallationProcessIdentity(pid);
      const names = ['mnt', 'pid', 'net', 'ipc', 'uts', 'user', 'cgroup'];
      const [links, cgroup, executable, status, mountinfo] = await Promise.all([
        Promise.all(names.map((name) => boundedLink(`/proc/${pid}/ns/${name}`))),
        boundedRead(`/proc/${pid}/cgroup`, caps.cgroup),
        owned(budget(), () => stat(`/proc/${pid}/exe`, { bigint: true })),
        boundedRead(`/proc/${pid}/status`, caps.status),
        boundedRead(`/proc/${pid}/mountinfo`, caps.mountinfo),
      ]);
      if (status.length > 65536 || mountinfo.length > 1048576 || cgroup.length > 8192) fail();
      // This observer supports the host cgroup-v2 hierarchy only. A namespaced,
      // remote or unsupported hierarchy must not be inferred from Docker config.
      const group = /^0::(\/[^\n]*)\n$/u.exec(cgroup)?.[1];
      if (!group || group.split('/').some((v) => v === '.' || v === '..') || group.includes('\0'))
        fail();
      const [memory, cpu, pids] = await Promise.all(
        ['memory.max', 'cpu.max', 'pids.max'].map(async (name) => {
          try {
            return await boundedRead(
              `/sys/fs/cgroup${group === '/' ? '' : group}/${name}`,
              caps.controller,
            );
          } catch (error) {
            assertBudget(budget());
            if (error?.code === 'ENOENT') return null;
            throw error;
          }
        }),
      );
      // A host desktop slice may not enable a controller. Preserve that absence;
      // target admission requires every actual finite limit, never this fallback.
      const cpuParts = cpu === null ? [null, null] : cpu.trim().split(' ');
      if (cpuParts.length !== 2) fail();
      const roots = mountinfo
        .trim()
        .split('\n')
        .map((line) => line.split(' '))
        .filter((v) => v[4] === '/');
      if (roots.length !== 1) fail();
      const root = roots[0];
      const security = {
        noNewPrivileges: Number(/^NoNewPrivs:\s+([01])$/mu.exec(status)?.[1]),
        seccomp: Number(/^Seccomp:\s+([012])$/mu.exec(status)?.[1]),
        capabilities: ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].map(
          (name) => new RegExp('^' + name + ':\\s+([0-9a-f]{16})$', 'mu').exec(status)?.[1],
        ),
        rootMountId: root[0],
        rootDevice: root[2],
        rootReadOnly: root[5].split(',').includes('ro'),
      };
      const after = await readInstallationProcessIdentity(pid);
      if (canonicalJson(before) !== canonicalJson(after) || !executable.isFile()) fail();
      return installationProcessIsolationSchema.parse({
        process: before,
        namespaces: Object.fromEntries(names.map((name, i) => [name, links[i]])),
        cgroup,
        executableDevice: String(executable.dev),
        executableInode: String(executable.ino),
        security,
        limits: {
          memoryBytes: memory?.trim() ?? null,
          cpuQuota: cpuParts[0],
          cpuPeriod: cpuParts[1],
          pids: pids?.trim() ?? null,
        },
      });
    } catch (cause) {
      throw new InstallationProcessObservationError(cause);
    }
  });
}
