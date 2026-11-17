import type { ZodType } from 'zod';
export interface InstallationProcessIdentity {
  pid: number;
  startTicks: string;
  bootId: string;
  startedAtMs: number;
  executable: string;
  uid: number;
}
export interface InstallationProcessIsolation {
  process: InstallationProcessIdentity;
  namespaces: Record<'mnt' | 'pid' | 'net' | 'ipc' | 'uts' | 'user' | 'cgroup', string>;
  cgroup: string;
  executableDevice: string;
  executableInode: string;
  security: {
    noNewPrivileges: number;
    seccomp: number;
    capabilities: string[];
    rootMountId: string;
    rootDevice: string;
    rootReadOnly: boolean;
  };
  limits: {
    memoryBytes: string | null;
    cpuQuota: string | null;
    cpuPeriod: string | null;
    pids: string | null;
  };
}
export const installationProcessIdentitySchema: ZodType<InstallationProcessIdentity>;
export const installationProcessIsolationSchema: ZodType<InstallationProcessIsolation>;
export function readInstallationProcessIdentity(
  pid: number,
  executableOverride?: string | Promise<string>,
): Promise<InstallationProcessIdentity>;
export function readInstallationProcessIsolation(
  pid: number,
): Promise<InstallationProcessIsolation>;
/** Shared resource deadline only; never authority or observation evidence. */
export function withInstallationProcessObservationBudget<T>(
  operation: () => Promise<T>,
): Promise<T>;
/** Bounded historical data only; cannot establish current installed authority. */
export function readInstallationProcessTcp4Table(pid: number): Promise<string>;
export function readInstallationProcessFileDescriptors(pid: number): Promise<
  readonly Readonly<{
    fd: string;
    target: string;
  }>[]
>;

export class InstallationProcessObservationError extends Error {
  constructor(cause?: unknown);
}
