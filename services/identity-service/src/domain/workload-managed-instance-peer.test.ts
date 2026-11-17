import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const io = vi.hoisted(() => ({
  now: 0,
  contents: new Map<string, string | Error>(),
  buffers: [] as Buffer[],
  opened: [] as string[],
  closed: [] as string[],
  readAt: undefined as undefined | (() => void),
  closeError: false,
  ticks: '100\n',
  stderr: '',
  childError: undefined as Error | undefined,
  childOptions: undefined as Record<string, unknown> | undefined,
  fds: [] as string[],
  links: new Map<string, string | Error>(),
  dirClosed: 0,
  dirCloseError: false,
  dirReadError: false,
  blockedPath: undefined as string | undefined,
  readGate: undefined as Promise<void> | undefined,
}));
vi.mock('node:perf_hooks', () => ({ performance: { now: () => io.now } }));
vi.mock('node:fs/promises', () => ({
  open: async (path: string) => {
    io.opened.push(path);
    const value = io.contents.get(path);
    if (value instanceof Error) throw value;
    if (value === undefined) throw Object.assign(new Error('missing fixture'), { code: 'ENOENT' });
    const source = Buffer.from(value);
    let position = 0;
    return {
      read: async (buffer: Buffer, offset: number, length: number) => {
        io.buffers.push(buffer);
        if (path === io.blockedPath) await io.readGate;
        io.readAt?.();
        const bytesRead = source.copy(buffer, offset, position, position + length);
        position += bytesRead;
        return { bytesRead };
      },
      close: async () => {
        io.closed.push(path);
        if (io.closeError) throw new Error('close failed');
      },
    };
  },
  opendir: async (_path: string, options: { bufferSize: number }) => {
    expect(options.bufferSize).toBe(8);
    let index = 0;
    return {
      read: async () => {
        if (io.dirReadError) throw new Error('directory read failed');
        const name = io.fds[index++];
        return name === undefined ? null : { name, isSymbolicLink: () => true };
      },
      close: async () => {
        io.dirClosed++;
        if (io.dirCloseError) throw new Error('directory close failed');
      },
    };
  },
  readlink: async (path: string) => {
    if (io.links.has(path)) {
      const value = io.links.get(path);
      if (value instanceof Error) throw value;
      return value;
    }
    return path.includes('/fd/')
      ? 'socket:[42]'
      : path.endsWith('/exe')
        ? '/usr/bin/node'
        : `${path.split('/').at(-1)}:[1]`;
  },
  stat: async () => ({ dev: 1n, ino: 2n, isFile: () => true }),
}));
vi.mock('node:child_process', async () => {
  const { EventEmitter } = await import('node:events');
  return {
    execFile: (
      _file: string,
      _args: string[],
      options: Record<string, unknown>,
      callback: (error: Error | undefined, stdout: string, stderr: string) => void,
    ) => {
      io.childOptions = options;
      const child = new EventEmitter();
      queueMicrotask(() => {
        callback(io.childError, io.ticks, io.stderr);
        child.emit('close', 0);
      });
      return child;
    },
  };
});
import {
  readInstallationProcessIdentity,
  readInstallationProcessIsolation,
  withInstallationProcessObservationBudget,
  readInstallationProcessFileDescriptors,
  readInstallationProcessTcp4Table,
} from '../../../../scripts/operations/installation-process-observation.mjs';
import { TLSSocket } from 'node:tls';
import {
  parseManagedWorkloadTcp4Table,
  correlateManagedWorkloadSocket,
  collectManagedWorkloadInstance,
  readCollectedManagedWorkloadInstance,
} from '../../../../scripts/operations/workload-managed-instance-observation.mjs';
import {
  managedWorkloadCopy,
  managedWorkloadDigest,
  managedWorkloadDescriptorFromHistoricalPins,
} from '../contracts/workload-managed-instance.js';
import {
  requireInstalledManagedWorkloadInstance,
  readAuthenticatedManagedWorkloadObservation,
} from './workload-managed-instance-peer.js';
import type { QualificationDeploymentPins } from '../../../../scripts/operations/qualification-deployment-observation.mjs';

beforeEach(() => {
  io.now = 0;
  io.contents.clear();
  io.buffers.length = 0;
  io.opened.length = 0;
  io.closed.length = 0;
  io.readAt = undefined;
  io.closeError = false;
  io.ticks = '100\n';
  io.stderr = '';
  io.childError = undefined;
  io.childOptions = undefined;
  io.fds = ['3'];
  io.links.clear();
  io.dirClosed = 0;
  io.dirCloseError = false;
  io.dirReadError = false;
  io.blockedPath = undefined;
  io.readGate = undefined;
  io.contents.set('/proc/7/stat', `7 (fixture) S ${Array(18).fill('0').join(' ')} 100\n`);
  io.contents.set(
    '/proc/7/status',
    'Uid:\t1\t1\t1\t1\nNoNewPrivs:\t1\nSeccomp:\t2\n' +
      ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']
        .map((key) => `${key}:\t0000000000000000\n`)
        .join(''),
  );
  io.contents.set('/proc/sys/kernel/random/boot_id', '11111111-1111-4111-8111-111111111111\n');
  io.contents.set('/proc/stat', 'cpu 0\nbtime 1\n');
  io.contents.set('/proc/7/cgroup', '0::/fixture\n');
  io.contents.set('/proc/7/mountinfo', '1 0 0:1 / / ro - tmpfs tmpfs ro\n');
});

const uuid = (value: number) => `018f0000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const hash = (value: string) => 'sha256:' + value.repeat(64);
function historicalPins(): QualificationDeploymentPins {
  return {
    schemaVersion: 1,
    installationId: uuid(1),
    participantId: uuid(2),
    privacyDomainId: uuid(3),
    environmentId: 'test-deployment',
    operationsInstallationDigest: hash('1'),
    peer: {
      principalId: uuid(4),
      credentialId: uuid(5),
      participantEpoch: '1',
      principalEpoch: '1',
      credentialEpoch: '1',
      workloadId: 'urn:openpc:workload:' + uuid(4),
      keyDigest: hash('2'),
      certificateDigest: hash('3'),
    },
    daemonId: 'test-engine',
    engineEndpoint: 'unix:///var/run/docker.sock',
    containerId: 'a'.repeat(64),
    imageId: hash('4'),
    containerStartedAt: '2026-09-26T00:00:00Z',
    installedProcess: {
      process: {
        pid: 7,
        startTicks: '100',
        bootId: '11111111-1111-4111-8111-111111111111',
        startedAtMs: 2000,
        executable: '/usr/bin/node',
        uid: 1,
      },
      namespaces: {
        mnt: 'mnt:[1]',
        pid: 'pid:[1]',
        net: 'net:[1]',
        ipc: 'ipc:[1]',
        uts: 'uts:[1]',
        user: 'user:[1]',
        cgroup: 'cgroup:[1]',
      },
      cgroup: '0::/fixture\n',
      executableDevice: '1',
      executableInode: '2',
      security: {
        noNewPrivileges: 1,
        seccomp: 2,
        capabilities: Array<string>(5).fill('0000000000000000'),
        rootMountId: '1',
        rootDevice: '0:1',
        rootReadOnly: true,
      },
      limits: { memoryBytes: '67108864', cpuQuota: '50000', cpuPeriod: '100000', pids: '32' },
    },
    expectedUid: 1,
    executable: '/usr/bin/node',
    argv: [],
    networkId: 'b'.repeat(64),
    address: '172.20.0.2',
    memoryBytes: 67108864,
    nanoCpus: 500000000,
    pidsLimit: 32,
    mounts: [],
    tmpfsTargets: [],
    artifacts: [{ path: '/app/runtime', digest: hash('5'), maximumBytes: 1024 }],
    separatedFrom: [],
  };
}
const instance = { registrationId: uuid(6), instanceId: uuid(7), instanceGeneration: '1' };
const connection = {
  profile: 'LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1' as const,
  family: 'IPv4' as const,
  remoteAddress: '172.20.0.2',
  remotePort: 50000,
  localAddress: '172.20.0.1',
  localPort: 443,
};
const header =
  '  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n';
const row =
  '0: 020014AC:C350 010014AC:01BB 01 00000000:00000000 00:00000000 00000000 1 0 42 1 0000000000000000 100 0 0 10 -1';
describe('managed observation data boundaries (pure inputs, no native authority)', () => {
  it('decodes the complete Linux tuple and correlates only its reversed server socket', () => {
    expect(parseManagedWorkloadTcp4Table(header + row + '\n')).toHaveLength(1);
    expect(
      correlateManagedWorkloadSocket(
        header + row + '\n',
        [{ fd: '3', target: 'socket:[42]' }],
        connection,
      ),
    ).toEqual({ fd: '3', inode: '42', uid: '1', connection });
  });
  it('accepts only complete short timewait/request records with zero inode', () => {
    const fields = row.split(' ');
    fields[3] = '06';
    fields[9] = '0';
    expect(
      parseManagedWorkloadTcp4Table(header + fields.slice(0, 12).join(' ') + '\n'),
    ).toHaveLength(1);
    fields[3] = '01';
    expect(() =>
      parseManagedWorkloadTcp4Table(header + fields.slice(0, 12).join(' ') + '\n'),
    ).toThrow();
  });
  it.each([
    row.slice(0, -3),
    row.replace(' 01 ', ' 00 '),
    row.replace('020014AC', 'GG0014AC'),
    row.replace(' 42 ', ' 18446744073709551616 '),
  ])('rejects incomplete/malformed TCP records', (value) => {
    expect(() => parseManagedWorkloadTcp4Table(header + value + '\n')).toThrow();
  });
  it('rejects missing EOF newline, excess table bytes and duplicate slots', () => {
    expect(() => parseManagedWorkloadTcp4Table(header + row)).toThrow();
    expect(() => parseManagedWorkloadTcp4Table(header + 'x'.repeat(262144) + '\n')).toThrow();
    expect(() => parseManagedWorkloadTcp4Table(header + row + '\n' + row + '\n')).toThrow();
  });
  it('rejects duplicate tuple or FD ownership and missing FD match', () => {
    const fds = [{ fd: '3', target: 'socket:[42]' }];
    expect(() =>
      correlateManagedWorkloadSocket(
        header + row + '\n' + row.replace('0: ', '1: ') + '\n',
        fds,
        connection,
      ),
    ).toThrow();
    expect(() =>
      correlateManagedWorkloadSocket(
        header + row + '\n',
        [...fds, { fd: '4', target: 'socket:[42]' }],
        connection,
      ),
    ).toThrow();
    expect(() => correlateManagedWorkloadSocket(header + row + '\n', [], connection)).toThrow();
  });
  it('rejects unestablished, proxy, changed-port and IPv6 connections', () => {
    for (const changed of [
      { ...connection, remotePort: 50001 },
      { ...connection, remoteAddress: '172.20.0.3' },
      { ...connection, family: 'IPv6', remoteAddress: '::ffff:172.20.0.2' },
    ])
      expect(() =>
        correlateManagedWorkloadSocket(
          header + row + '\n',
          [{ fd: '3', target: 'socket:[42]' }],
          changed as typeof connection,
        ),
      ).toThrow();
    expect(() =>
      correlateManagedWorkloadSocket(
        header + row.replace(' 01 ', ' 08 ') + '\n',
        [{ fd: '3', target: 'socket:[42]' }],
        connection,
      ),
    ).toThrow();
  });
  it('makes the stable descriptor independent of every original leaf field and preserves original bytes', () => {
    const pins = historicalPins(),
      original = JSON.stringify(pins),
      first = managedWorkloadDescriptorFromHistoricalPins(pins, instance);
    const next = {
      ...pins,
      peer: {
        ...pins.peer,
        credentialId: uuid(9),
        participantEpoch: '2',
        principalEpoch: '3',
        credentialEpoch: '4',
        keyDigest: hash('a'),
        certificateDigest: hash('b'),
      },
    };
    expect(managedWorkloadDescriptorFromHistoricalPins(next, instance)).toEqual(first);
    expect(JSON.stringify(pins)).toBe(original);
    expect(() =>
      managedWorkloadDescriptorFromHistoricalPins(pins, {
        ...instance,
        registrationId: pins.installationId,
      }),
    ).toThrow();
    expect(
      managedWorkloadDescriptorFromHistoricalPins({ ...pins, imageId: hash('c') }, instance)
        .stableInstallationDigest,
    ).not.toBe(first.stableInstallationDigest);
  });
  it('never invokes own getters or reads proxy properties after the descriptor snapshot', () => {
    const getter = vi.fn(() => 1),
      value = {};
    Object.defineProperty(value, 'value', { get: getter, enumerable: true });
    expect(() => managedWorkloadCopy(value)).toThrow();
    expect(getter).not.toHaveBeenCalled();
    const read = vi.fn(() => 'changed'),
      proxy = new Proxy({ value: 'original' }, { get: read });
    expect(managedWorkloadCopy(proxy)).toEqual({ value: 'original' });
    expect(read).not.toHaveBeenCalled();
    expect(managedWorkloadDigest(proxy)).toBe(managedWorkloadDigest({ value: 'original' }));
  });
  it('rejects sparse arrays, exotic prototypes, symbols and oversized data', () => {
    const sparse = new Array(1);
    expect(() => managedWorkloadCopy(sparse)).toThrow();
    expect(() => managedWorkloadCopy(Object.create({ value: 1 }) as unknown)).toThrow();
    expect(() => managedWorkloadCopy({ [Symbol('private')]: 1 })).toThrow();
    expect(() => managedWorkloadCopy('x'.repeat(65537))).toThrow();
  });
  it('does not let JSON, cloned handles or caller TLS fields mint native/authenticated authority', async () => {
    expect(() =>
      readCollectedManagedWorkloadInstance(
        {} as Parameters<typeof readCollectedManagedWorkloadInstance>[0],
      ),
    ).toThrow();
    expect(() =>
      readAuthenticatedManagedWorkloadObservation(
        {} as Parameters<typeof readAuthenticatedManagedWorkloadObservation>[0],
      ),
    ).toThrow();
    const pins = historicalPins(),
      descriptor = managedWorkloadDescriptorFromHistoricalPins(pins, instance);
    const fake = { authorized: true, getProtocol: () => 'TLSv1.3' } as unknown as TLSSocket;
    await expect(
      collectManagedWorkloadInstance(pins, [], descriptor, fake, {
        observationId: uuid(8),
        requestDigest: hash('a'),
      }),
    ).rejects.toThrow();
    expect(io.opened).toEqual([]);
    await expect(requireInstalledManagedWorkloadInstance()).rejects.toThrow(
      'MANAGED_WORKLOAD_INSTANCE_UNINSTALLED',
    );
  });
});
afterEach(() => vi.useRealTimers());

describe('shared process-observation resource scope (mocked IO only)', () => {
  it('preserves the legacy identity and owns every descriptor through zeroization and close', async () => {
    expect(await readInstallationProcessIdentity(7)).toEqual({
      pid: 7,
      startTicks: '100',
      bootId: '11111111-1111-4111-8111-111111111111',
      startedAtMs: 2000,
      executable: '/usr/bin/node',
      uid: 1,
    });
    expect(io.closed.sort()).toEqual(io.opened.sort());
    expect(io.buffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    expect(io.childOptions).toMatchObject({ timeout: 2000, maxBuffer: 256, killSignal: 'SIGKILL' });
  });
  it.each([0, -1, 1.1, NaN, Infinity, 2147483648])('denies PID %s before IO', async (pid) => {
    await expect(readInstallationProcessIdentity(pid)).rejects.toThrow();
    expect(io.opened).toEqual([]);
  });
  it.each(['/proc/7/stat', '/proc/7/status', '/proc/sys/kernel/random/boot_id', '/proc/stat'])(
    'rejects overflow with fixed buffers and closes all parallel descriptors: %s',
    async (path) => {
      io.contents.set(path, 'x'.repeat(1048577));
      await expect(readInstallationProcessIdentity(7)).rejects.toThrow();
      expect(io.closed.sort()).toEqual(io.opened.sort());
      expect(
        io.buffers.every(
          (buffer) => buffer.length <= 1048577 && buffer.every((byte) => byte === 0),
        ),
      ).toBe(true);
    },
  );
  it('denies late reads and nested budget renewal', async () => {
    io.readAt = () => {
      io.now = 30001;
    };
    await expect(
      withInstallationProcessObservationBudget(() => {
        io.now = 20000;
        return readInstallationProcessIsolation(7);
      }),
    ).rejects.toThrow();
    expect(io.closed.sort()).toEqual(io.opened.sort());
  });
  it('denies descriptor cleanup failure', async () => {
    io.closeError = true;
    await expect(readInstallationProcessIdentity(7)).rejects.toThrow();
    expect(io.closed.sort()).toEqual(io.opened.sort());
  });
  it('waits for OUR parallel read/close settlement after a sibling fails', async () => {
    io.contents.set('/proc/7/stat', 'x'.repeat(8193));
    let release: () => void = () => {
      throw new Error('gate not established');
    };
    io.blockedPath = '/proc/7/status';
    io.readGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let settled = false;
    const pending = readInstallationProcessIdentity(7);
    void pending.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(settled).toBe(false);
    release();
    await expect(pending).rejects.toThrow();
    expect(io.closed.sort()).toEqual(io.opened.sort());
  });
  it.each(['100\nextra', '0\n', '1e2\n', '1000000000\n'])(
    'denies malformed getconf output %s',
    async (ticks) => {
      io.ticks = ticks;
      await expect(readInstallationProcessIdentity(7)).rejects.toThrow();
    },
  );
  it('denies child output errors', async () => {
    io.childError = new Error('output overflow');
    await expect(readInstallationProcessIdentity(7)).rejects.toThrow();
  });
  it('retains a legacy executable promise without making it authority', async () => {
    expect(
      (await readInstallationProcessIdentity(7, Promise.resolve('/legacy/fact'))).executable,
    ).toBe('/legacy/fact');
  });
  it('does not wait indefinitely for a caller-owned legacy promise', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const pending = expect(
      readInstallationProcessIdentity(7, new Promise<string>(() => {})),
    ).rejects.toThrow();
    await vi.advanceTimersByTimeAsync(30000);
    await pending;
    expect(io.closed.sort()).toEqual(io.opened.sort());
  });
  it('keeps only actual absent cgroup controllers nullable', async () => {
    expect((await readInstallationProcessIsolation(7)).limits).toEqual({
      memoryBytes: null,
      cpuQuota: null,
      cpuPeriod: null,
      pids: null,
    });
    io.contents.set(
      '/sys/fs/cgroup/fixture/memory.max',
      Object.assign(new Error('permission denied'), { code: 'EACCES' }),
    );
    await expect(readInstallationProcessIsolation(7)).rejects.toThrow();
  });
  it('rejects controller overflow rather than reporting absence', async () => {
    io.contents.set('/sys/fs/cgroup/fixture/memory.max', '1'.repeat(129));
    await expect(readInstallationProcessIsolation(7)).rejects.toThrow();
  });
  it('does not swallow a non-Error rejection from a resource callback', async () => {
    await expect(
      withInstallationProcessObservationBudget(async () => {
        throw null;
      }),
    ).rejects.toBeNull();
  });
  it('bounds TCP bytes before returning any historical table', async () => {
    io.contents.set('/proc/7/net/tcp', 'x'.repeat(262144));
    expect((await readInstallationProcessTcp4Table(7)).length).toBe(262144);
    io.contents.set('/proc/7/net/tcp', 'x'.repeat(262145));
    await expect(readInstallationProcessTcp4Table(7)).rejects.toThrow();
    expect(io.closed.sort()).toEqual(io.opened.sort());
    expect(
      io.buffers.every((buffer) => buffer.length === 262145 && buffer.every((byte) => byte === 0)),
    ).toBe(true);
  });
  it('enumerates exactly1024 entries incrementally and detects the1025th', async () => {
    io.fds = Array.from({ length: 1024 }, (_, i) => String(i));
    const actual = await readInstallationProcessFileDescriptors(7);
    expect(actual).toHaveLength(1024);
    expect(Object.isFrozen(actual)).toBe(true);
    expect(io.dirClosed).toBe(1);
    io.fds.push('1024');
    await expect(readInstallationProcessFileDescriptors(7)).rejects.toThrow();
    expect(io.dirClosed).toBe(2);
  });
  it.each(['../exe', '03', '-1', '2147483648', '1\0'])(
    'denies unsafe FD path %s and closes the directory',
    async (name) => {
      io.fds = [name];
      await expect(readInstallationProcessFileDescriptors(7)).rejects.toThrow();
      expect(io.dirClosed).toBe(1);
    },
  );
  it('denies duplicate FD names', async () => {
    io.fds = ['3', '3'];
    await expect(readInstallationProcessFileDescriptors(7)).rejects.toThrow();
    expect(io.dirClosed).toBe(1);
  });
  it('denies disappearing FD links rather than returning a partial list', async () => {
    io.fds = ['3', '4'];
    io.links.set('/proc/7/fd/4', Object.assign(new Error('disappeared'), { code: 'ENOENT' }));
    await expect(readInstallationProcessFileDescriptors(7)).rejects.toThrow();
    expect(io.dirClosed).toBe(1);
  });
  it('denies directory cleanup failure and preserves the original read failure', async () => {
    io.dirReadError = true;
    io.dirCloseError = true;
    try {
      await readInstallationProcessFileDescriptors(7);
      throw new Error('unexpected success');
    } catch (error) {
      expect(error).toHaveProperty('cause');
      expect(
        (error as Error & { cause: AggregateError }).cause.errors.map(
          (value: Error) => value.message,
        ),
      ).toEqual(['directory read failed', 'directory close failed']);
    }
    expect(io.dirClosed).toBe(1);
  });
  it('denies targets exceeding the total result bound', async () => {
    io.fds = Array.from({ length: 65 }, (_, i) => String(i));
    for (const name of io.fds) io.links.set(`/proc/7/fd/${name}`, 'x'.repeat(4096));
    await expect(readInstallationProcessFileDescriptors(7)).rejects.toThrow();
    expect(io.dirClosed).toBe(1);
  });
});
