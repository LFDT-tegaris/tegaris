import type { ZodType } from 'zod';
import type { InstallationProcessIsolation } from './installation-process-observation.mjs';
export interface QualificationDeploymentPeer {
  principalId: string;
  credentialId: string;
  participantEpoch: string;
  principalEpoch: string;
  credentialEpoch: string;
  workloadId: string;
  keyDigest: string;
  certificateDigest: string;
}
export interface QualificationDeploymentSelection {
  participantId: string;
  privacyDomainId: string;
  installationId: string;
}
export interface QualificationDeploymentIntent {
  observationId: string;
  operationId: string;
}
export interface QualificationDeploymentPins extends QualificationDeploymentSelection {
  schemaVersion: 1;
  environmentId: string;
  operationsInstallationDigest: string;
  peer: QualificationDeploymentPeer;
  daemonId: string;
  engineEndpoint: 'unix:///var/run/docker.sock';
  containerId: string;
  imageId: string;
  containerStartedAt: string;
  installedProcess: InstallationProcessIsolation;
  expectedUid: number;
  executable: string;
  argv: string[];
  networkId: string;
  address: string;
  memoryBytes: number;
  nanoCpus: number;
  pidsLimit: number;
  mounts: { source: string; target: string; kind: 'CREDENTIAL' | 'SCRATCH'; readOnly: boolean }[];
  tmpfsTargets: string[];
  artifacts: { path: string; digest: string; maximumBytes: number }[];
  separatedFrom: string[];
}
export interface QualificationDeploymentInstance {
  installationId: string;
  containerId: string;
  imageId: string;
  startedAt: string;
  process: InstallationProcessIsolation;
  networkId: string;
  address: string;
  endpointId: string;
  memoryBytes: number;
  nanoCpus: number;
  pidsLimit: number;
  mounts: {
    target: string;
    kind: 'CREDENTIAL' | 'SCRATCH' | 'TMPFS';
    readOnly: boolean;
    device: string | null;
    inode: string | null;
  }[];
}
export interface QualificationDeploymentMeasurement {
  schemaVersion: 1;
  observationId: string;
  requestDigest: string;
  installationDigest: string;
  startedAtMs: number;
  completedAtMs: number;
  scope: 'CONTAINER_WORKLOAD';
  daemon: { id: string; socketDevice: string; socketInode: string; hostBootId: string };
  instance: QualificationDeploymentInstance;
  separatedInstances: QualificationDeploymentInstance[];
  artifacts: { path: string; digest: string; bytes: number }[];
  sourceBuildLink: 'UNESTABLISHED';
  changeAuthorship: 'UNESTABLISHED';
  exactSocketProcess: 'UNESTABLISHED';
  qualification: 'UNESTABLISHED';
}
declare const nativeHandle: unique symbol;
export interface CollectedQualificationDeployment {
  readonly [nativeHandle]: true;
}
export const qualificationDeploymentPeerSchema: ZodType<QualificationDeploymentPeer>;
export const qualificationDeploymentSelectionSchema: ZodType<QualificationDeploymentSelection>;
export const qualificationDeploymentIntentSchema: ZodType<QualificationDeploymentIntent>;
export const qualificationDeploymentPinsSchema: ZodType<QualificationDeploymentPins>;
export const qualificationDeploymentMeasurementSchema: ZodType<QualificationDeploymentMeasurement>;
export function deploymentCopy<T>(value: T): T;
export function parseQualificationDeploymentPins(value: unknown): QualificationDeploymentPins;
export function qualificationDeploymentDigest(value: unknown): string;
export function validateQualificationArtifactMetadata(
  value: unknown,
  directory: boolean,
  maximumBytes: number,
): {
  mode: number;
  links: string;
  size: number;
  device: string;
  inode: string;
  modifiedNs: string;
  changedNs: string;
};
export function readQualificationPublicArtifactArchive(
  bytes: Buffer,
  path: string,
  maximumBytes: number,
): { digest: string; bytes: number };
export function validateQualificationContainerSnapshot(
  pins: unknown,
  actual: Record<string, unknown>,
  process: InstallationProcessIsolation,
  host: InstallationProcessIsolation,
): unknown;
export function collectQualificationDeployment(
  pins: QualificationDeploymentPins,
  otherPins: QualificationDeploymentPins[],
  connection: { remoteAddress: string; localAddress: string },
  attempt: { observationId: string; requestDigest: string },
): Promise<CollectedQualificationDeployment>;
export function readCollectedQualificationDeployment(
  handle: CollectedQualificationDeployment,
): QualificationDeploymentMeasurement;
