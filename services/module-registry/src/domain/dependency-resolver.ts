import { ContractError } from './errors.js';
import { sha256 } from './digest.js';

export interface ModuleNode {
  moduleId: string;
  semanticVersion: string;
  manifestDigest: string;
  capabilities: readonly string[];
  future?: boolean;
}
export interface ExactDependency {
  edgeId: string;
  consumerModuleId: string;
  providerModuleId: string;
  capabilityId: string;
  semanticVersion: string;
  providerManifestDigest: string;
}

export function errorForNegativeProfile(profile: string): ContractError {
  const errors = {
    CYCLE: 'PC-MODULE-7002',
    MISSING_DEPENDENCY: 'PC-MODULE-7001',
    INCOMPATIBLE_VERSION: 'PC-MODULE-7003',
    DIGEST_MISMATCH: 'PC-MODULE-7003',
    CONFLICTING_PROVIDER: 'PC-MODULE-7004',
    ACTIVE_DEPENDENT: 'PC-MODULE-7005',
    UNCLOSED_DATA_CUSTODY: 'PC-MODULE-7006',
    FUTURE_HOST_AS_R1: 'PC-MODULE-7007',
  } as const;
  const code = errors[profile as keyof typeof errors];
  if (code === undefined) throw new ContractError('PC-MODULE-7000', 'unknown conformance profile');
  return new ContractError(code, profile);
}

export function resolveDependencies(
  nodes: readonly ModuleNode[],
  dependencies: readonly ExactDependency[],
) {
  const byId = new Map(nodes.map((node) => [node.moduleId, node]));
  const providers = new Map<string, string>();
  for (const edge of dependencies) {
    const consumer = byId.get(edge.consumerModuleId);
    const provider = byId.get(edge.providerModuleId);
    if (consumer === undefined || provider === undefined) throw new ContractError('PC-MODULE-7001');
    if (provider.future) throw new ContractError('PC-MODULE-7007');
    if (
      provider.semanticVersion !== edge.semanticVersion ||
      provider.manifestDigest !== edge.providerManifestDigest
    )
      throw new ContractError('PC-MODULE-7003');
    if (!provider.capabilities.includes(edge.capabilityId))
      throw new ContractError('PC-MODULE-7001');
    const providerKey = `${consumer.moduleId}:${edge.capabilityId}`;
    const prior = providers.get(providerKey);
    if (prior !== undefined && prior !== provider.moduleId)
      throw new ContractError('PC-MODULE-7004');
    providers.set(providerKey, provider.moduleId);
  }
  const incoming = new Map(nodes.map((node) => [node.moduleId, 0]));
  const outgoing = new Map(nodes.map((node) => [node.moduleId, [] as string[]]));
  for (const edge of dependencies) {
    outgoing.get(edge.providerModuleId)?.push(edge.consumerModuleId);
    incoming.set(edge.consumerModuleId, (incoming.get(edge.consumerModuleId) ?? 0) + 1);
  }
  const ready = [...incoming]
    .filter(([, count]) => count === 0)
    .map(([id]) => id)
    .sort();
  const order: string[] = [];
  while (ready.length > 0) {
    const id = ready.shift()!;
    order.push(id);
    for (const next of (outgoing.get(id) ?? []).sort()) {
      const count = (incoming.get(next) ?? 0) - 1;
      incoming.set(next, count);
      if (count === 0) {
        ready.push(next);
        ready.sort();
      }
    }
  }
  if (order.length !== nodes.length) throw new ContractError('PC-MODULE-7002');
  return Object.freeze({
    order: Object.freeze(order),
    closureDigest: sha256({
      nodes: [...nodes].sort((a, b) => a.moduleId.localeCompare(b.moduleId)),
      dependencies: [...dependencies].sort((a, b) => a.edgeId.localeCompare(b.edgeId)),
    }),
  });
}
