import { z } from 'zod';
import { createHash } from 'node:crypto';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  qualificationDeploymentPinsSchema,
  type QualificationDeploymentPins,
} from '../../../../scripts/operations/qualification-deployment-observation.mjs';

const id = z.uuidv7().regex(/^[0-9a-f-]+$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const generation = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
export const managedWorkloadInstanceDescriptorSchema = z
  .strictObject({
    domain: z.literal('pc.identity.workload-managed-instance.descriptor.v1'),
    version: z.literal(1),
    registrationId: id,
    instanceId: id,
    instanceGeneration: generation,
    participantId: id,
    privacyDomainId: id,
    environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
    principalId: id,
    workloadId: z
      .string()
      .regex(
        /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    historicalInstallationId: id,
    stableInstallationDigest: digest,
    processIdentityDigest: digest,
    networkNamespace: z.string().regex(/^net:\[[1-9][0-9]*\]$/u),
    connectionProfile: z.literal('LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1'),
  })
  .refine((v) => new Set([v.registrationId, v.instanceId, v.historicalInstallationId]).size === 3);
export type ManagedWorkloadInstanceDescriptor = z.infer<
  typeof managedWorkloadInstanceDescriptorSchema
>;

/** Closed bounded public records, including the original pins' plain arrays.
 * Never invoke getters or preserve mutable caller references while inspecting.
 * A successful parse/copy is DATA ONLY, not installed selection or authority. */
function snapshotManagedWorkloadData(value: unknown): unknown {
  const budget = { nodes: 0, units: 0 };
  const visit = (v: unknown, depth: number): unknown => {
    if (++budget.nodes > 8192 || depth > 8) throw new Error('Invalid managed workload data');
    if (v === null || typeof v === 'boolean') return v;
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new Error('Invalid managed workload number');
      return v;
    }
    if (typeof v === 'string') {
      budget.units += v.length;
      if (v.length > 65536 || budget.units > 262144)
        throw new Error('Invalid managed workload data size');
      return v;
    }
    const array = Array.isArray(v);
    if (
      !v ||
      typeof v !== 'object' ||
      Object.getPrototypeOf(v) !== (array ? Array.prototype : Object.prototype)
    )
      throw new Error('Invalid managed workload record');
    const keys = Reflect.ownKeys(v);
    if (keys.length > 8193) throw new Error('Invalid managed workload key count');
    let arrayLength = 0;
    if (array) {
      const length = Object.getOwnPropertyDescriptor(v, 'length');
      if (
        !length ||
        !('value' in length) ||
        !Number.isSafeInteger(length.value) ||
        length.value < 0 ||
        length.value > 8192 ||
        keys.length !== length.value + 1
      )
        throw new Error('Invalid managed workload array');
      arrayLength = length.value;
    }
    const entries: [string, unknown][] = [];
    for (const key of keys) {
      const d = Object.getOwnPropertyDescriptor(v, key);
      if (
        array &&
        key === 'length' &&
        d &&
        'value' in d &&
        Number.isSafeInteger(d.value) &&
        d.value >= 0 &&
        d.value <= 8192
      )
        continue;
      if (
        typeof key !== 'string' ||
        !d?.enumerable ||
        !('value' in d) ||
        (array && (!/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= arrayLength))
      )
        throw new Error('Invalid managed workload property');
      budget.units += key.length;
      if (budget.units > 262144) throw new Error('Invalid managed workload data size');
      entries.push([key, visit(d.value, depth + 1)]);
    }
    if (!array) return Object.fromEntries(entries);
    const result = new Array<unknown>(arrayLength);
    for (const [key, entry] of entries)
      Object.defineProperty(result, key, {
        value: entry,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    return result;
  };
  return visit(value, 0);
}
export function assertManagedWorkloadData(value: unknown): void {
  snapshotManagedWorkloadData(value);
}
export function managedWorkloadCopy<T>(value: T): T {
  // Never read input properties again after reflecting their own DATA values.
  const copy = snapshotManagedWorkloadData(value) as T;
  const freeze = (v: unknown) => {
    if (v && typeof v === 'object') {
      for (const entry of Object.values(v)) freeze(entry);
      Object.freeze(v);
    }
  };
  freeze(copy);
  return copy;
}
export function managedWorkloadDigest(value: unknown): string {
  return (
    'sha256:' +
    createHash('sha256')
      .update(canonicalDefinitionJson(managedWorkloadCopy(value)))
      .digest('hex')
  );
}

/** PASSIVE stable projection of an unchanged original installation snapshot.
 * All leaf-specific peer fields are excluded. This does NOT admit a managed
 * registration or promote old qualification/history to current authority.
 * A subsequent independent registry must select and qualify this descriptor. */
export function managedWorkloadDescriptorFromHistoricalPins(
  input: QualificationDeploymentPins,
  instance: {
    readonly registrationId: string;
    readonly instanceId: string;
    readonly instanceGeneration: string;
  },
): ManagedWorkloadInstanceDescriptor {
  const pins = qualificationDeploymentPinsSchema.parse(managedWorkloadCopy(input));
  const identity = z
    .strictObject({ registrationId: id, instanceId: id, instanceGeneration: generation })
    .parse(managedWorkloadCopy(instance));
  const { peer, schemaVersion: _, ...installation } = pins;
  void _;
  const stableInstallationDigest = managedWorkloadDigest({
    domain: 'pc.identity.workload-managed-instance.stable-installation.v1',
    version: 1,
    installation,
    identity: { principalId: peer.principalId, workloadId: peer.workloadId },
  });
  return managedWorkloadCopy(
    managedWorkloadInstanceDescriptorSchema.parse({
      domain: 'pc.identity.workload-managed-instance.descriptor.v1',
      version: 1,
      ...identity,
      participantId: pins.participantId,
      privacyDomainId: pins.privacyDomainId,
      environmentId: pins.environmentId,
      principalId: peer.principalId,
      workloadId: peer.workloadId,
      historicalInstallationId: pins.installationId,
      stableInstallationDigest,
      processIdentityDigest: managedWorkloadDigest(pins.installedProcess),
      networkNamespace: pins.installedProcess.namespaces.net,
      connectionProfile: 'LINUX_DOCKER_BRIDGE_DIRECT_TCP4_V1',
    }),
  );
}
