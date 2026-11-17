import type { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import type { IdentityKernel } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import {
  managedWorkloadCopy,
  managedWorkloadDigest,
  managedWorkloadInstanceDescriptorSchema,
  type ManagedWorkloadInstanceDescriptor,
} from '../contracts/workload-managed-instance.js';
import {
  collectManagedWorkloadInstance,
  readCollectedManagedWorkloadInstance,
  readManagedWorkloadTransport,
  type ManagedWorkloadInstanceMeasurement,
} from '../../../../scripts/operations/workload-managed-instance-observation.mjs';
import type { QualificationDeploymentPins } from '../../../../scripts/operations/qualification-deployment-observation.mjs';
import { withInstallationProcessObservationBudget } from '../../../../scripts/operations/installation-process-observation.mjs';

export class ManagedWorkloadInstanceUnavailableError extends Error {
  constructor() {
    super('MANAGED_WORKLOAD_INSTANCE_UNINSTALLED');
  }
}
declare const authenticatedHistory: unique symbol;
export interface AuthenticatedManagedWorkloadObservation {
  readonly [authenticatedHistory]: true;
}
export interface AuthenticatedManagedWorkloadMeasurement {
  readonly domain: 'pc.identity.workload-managed-instance.authenticated-history.v1';
  readonly version: 1;
  readonly native: ManagedWorkloadInstanceMeasurement;
  readonly authenticatedIdentity: Readonly<{
    participantId: string;
    principalId: string;
    credentialId: string;
    workloadId: string;
    participantEpoch: string;
    principalEpoch: string;
    workloadEpoch: string;
    keyId: string;
    uriSan: string;
    notBefore: string;
    notAfter: string;
  }>;
  readonly registration: 'UNESTABLISHED';
}
const issued = new WeakMap<
  AuthenticatedManagedWorkloadObservation,
  AuthenticatedManagedWorkloadMeasurement
>();
function same(a: unknown, b: unknown) {
  if (managedWorkloadDigest(a) !== managedWorkloadDigest(b))
    throw new ManagedWorkloadInstanceUnavailableError();
}

/** Trusted server composition for HISTORICAL evidence, never admission/lease.
 * Native IO finishes outside all business locks. The existing C04 owner then
 * authenticates and rechecks the SAME actual TLS/credential occurrence. The
 * native process bracket is historical; it cannot prove continuous custody.
 * No descriptor, qualification row or callback supplies registry authority. */
export async function collectAuthenticatedManagedWorkloadObservation(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  pins: QualificationDeploymentPins,
  otherPins: QualificationDeploymentPins[],
  descriptor: ManagedWorkloadInstanceDescriptor,
  attempt: { readonly observationId: string; readonly requestDigest: string },
): Promise<AuthenticatedManagedWorkloadObservation> {
  const d = managedWorkloadInstanceDescriptorSchema.parse(managedWorkloadCopy(descriptor));
  const result = await withInstallationProcessObservationBudget(async () => {
    const nativeHandle = await collectManagedWorkloadInstance(pins, otherPins, d, socket, attempt);
    const native = readCollectedManagedWorkloadInstance(nativeHandle);
    const identity = await withAuthenticatedWorkloadPeer(
      pool,
      kernel,
      socket,
      async (_client, current, confirmCurrent) => {
        // No procfs, Docker, user callback or external effect under C04 locks.
        await confirmCurrent();
        same(readManagedWorkloadTransport(socket), native.transport);
        if (
          current.participantId !== d.participantId ||
          current.principalId !== d.principalId ||
          current.workloadId !== d.workloadId ||
          current.keyId !== native.transport.keyDigest ||
          current.uriSan !== native.transport.uriSan ||
          current.notBefore.toISOString() !== native.transport.notBefore ||
          current.notAfter.toISOString() !== native.transport.notAfter
        )
          throw new ManagedWorkloadInstanceUnavailableError();
        const copy = managedWorkloadCopy({
          participantId: current.participantId,
          principalId: current.principalId,
          credentialId: current.credentialId,
          workloadId: current.workloadId,
          participantEpoch: current.participantEpoch,
          principalEpoch: current.principalEpoch,
          workloadEpoch: current.workloadEpoch,
          keyId: current.keyId,
          uriSan: current.uriSan,
          notBefore: current.notBefore.toISOString(),
          notAfter: current.notAfter.toISOString(),
        });
        await confirmCurrent();
        same(readManagedWorkloadTransport(socket), native.transport);
        return copy;
      },
      { privacyDomainId: d.privacyDomainId },
    );
    same(readManagedWorkloadTransport(socket), native.transport);
    return managedWorkloadCopy({
      domain: 'pc.identity.workload-managed-instance.authenticated-history.v1' as const,
      version: 1 as const,
      native,
      authenticatedIdentity: identity,
      registration: 'UNESTABLISHED' as const,
    });
  });
  const handle = Object.freeze({}) as AuthenticatedManagedWorkloadObservation;
  issued.set(handle, result);
  return handle;
}
/** Private server handle custody only; JSON/structural clones cannot read it. */
export function readAuthenticatedManagedWorkloadObservation(
  handle: AuthenticatedManagedWorkloadObservation,
): AuthenticatedManagedWorkloadMeasurement {
  const value = issued.get(handle);
  if (!value) throw new ManagedWorkloadInstanceUnavailableError();
  return managedWorkloadCopy(value);
}
/** The installed managed-registry producer does not exist yet. Fail closed,
 * with no injected reader/fallback and no historical evidence promotion. */
export async function requireInstalledManagedWorkloadInstance(): Promise<never> {
  throw new ManagedWorkloadInstanceUnavailableError();
}
