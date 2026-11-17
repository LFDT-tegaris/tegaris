import type { ZodType } from 'zod';
import type { TLSSocket } from 'node:tls';
import type {
  QualificationDeploymentPins,
  QualificationDeploymentMeasurement,
} from './qualification-deployment-observation.mjs';
import type { InstallationProcessIsolation } from './installation-process-observation.mjs';
import type { ManagedWorkloadInstanceDescriptor } from '../../services/identity-service/src/contracts/workload-managed-instance.js';
export interface ManagedWorkloadConnection {
  readonly profile: 'LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1';
  readonly family: 'IPv4';
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly localAddress: string;
  readonly localPort: number;
}
export interface ManagedWorkloadTcp4Row {
  readonly localAddress: string;
  readonly localPort: number;
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly state: string;
  readonly inode: string;
  readonly uid: string;
}
export const managedWorkloadConnectionSchema: ZodType<ManagedWorkloadConnection>;
/** Pure data decoders; neither function mints a native observation handle. */
export function parseManagedWorkloadTcp4Table(text: string): readonly ManagedWorkloadTcp4Row[];
export function correlateManagedWorkloadSocket(
  text: string,
  fdLinks: readonly { readonly fd: string; readonly target: string }[],
  connection: ManagedWorkloadConnection,
): Readonly<{ fd: string; inode: string; uid: string; connection: ManagedWorkloadConnection }>;
export interface ManagedWorkloadInstanceMeasurement {
  readonly domain: 'pc.identity.workload-managed-instance.native-observation.v1';
  readonly version: 1;
  readonly observationId: string;
  readonly requestDigest: string;
  readonly descriptor: ManagedWorkloadInstanceDescriptor;
  readonly descriptorDigest: string;
  readonly startedAtMs: number;
  readonly completedAtMs: number;
  readonly transport: Readonly<{
    connection: ManagedWorkloadConnection;
    participantId: string;
    workloadId: string;
    uriSan: string;
    certificateDigest: string;
    keyDigest: string;
    notBefore: string;
    notAfter: string;
  }>;
  readonly process: InstallationProcessIsolation;
  readonly socket: Readonly<{
    fd: string;
    inode: string;
    uid: string;
    connection: ManagedWorkloadConnection;
  }>;
  readonly historicalQualification: QualificationDeploymentMeasurement;
  readonly registration: 'UNESTABLISHED';
  readonly continuousOwnership: 'UNESTABLISHED';
  readonly privateKeyCustody: 'UNESTABLISHED';
}
declare const nativeHandle: unique symbol;
export interface CollectedManagedWorkloadInstance {
  readonly [nativeHandle]: true;
}
export function collectManagedWorkloadInstance(
  pins: QualificationDeploymentPins,
  otherPins: QualificationDeploymentPins[],
  descriptor: ManagedWorkloadInstanceDescriptor,
  socket: TLSSocket,
  attempt: { readonly observationId: string; readonly requestDigest: string },
): Promise<CollectedManagedWorkloadInstance>;
/** Only the original native handle can return historical data, never admission. */
export function readCollectedManagedWorkloadInstance(
  handle: CollectedManagedWorkloadInstance,
): ManagedWorkloadInstanceMeasurement;
/** Genuine TLS snapshot data only; does not mint a native/authority handle. */
export function readManagedWorkloadTransport(
  socket: TLSSocket,
): ManagedWorkloadInstanceMeasurement['transport'];
