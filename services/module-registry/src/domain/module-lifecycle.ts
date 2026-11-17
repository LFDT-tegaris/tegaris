import { ContractError } from './errors.js';

export type ModuleState =
  | 'ABSENT'
  | 'ADMITTED'
  | 'INSTALLED_DISABLED'
  | 'ENABLING'
  | 'ENABLED'
  | 'DISABLING'
  | 'UPGRADING'
  | 'DOWNGRADING'
  | 'ROLLING_BACK'
  | 'UNINSTALLING'
  | 'REMOVED'
  | 'FAILED_FENCED';
export type ModuleOperation =
  'INSTALL' | 'ENABLE' | 'DISABLE' | 'UPGRADE' | 'DOWNGRADE' | 'ROLLBACK' | 'UNINSTALL' | 'RESOLVE';
export interface ModuleAggregate {
  state: ModuleState;
  aggregateVersion: bigint;
  manifestDigest: string;
  authorityEpoch: bigint;
  delegationEpoch: bigint;
}
export interface ModulePreflight {
  expectedVersion: bigint;
  authorityEpoch: bigint;
  delegationEpoch: bigint;
  approvalValid: boolean;
  distinctChecker: boolean;
  dependencyClosed: boolean;
  custodyClosed: boolean;
  activeDependents: number;
  simulationSuccessful: boolean;
  supplyChainValid: boolean;
}

const allowed: Record<ModuleOperation, readonly ModuleState[]> = {
  INSTALL: ['ABSENT'],
  ENABLE: ['INSTALLED_DISABLED'],
  DISABLE: ['ENABLED'],
  UPGRADE: ['ENABLED'],
  DOWNGRADE: ['ENABLED'],
  ROLLBACK: ['ENABLED'],
  UNINSTALL: ['INSTALLED_DISABLED'],
  RESOLVE: ['ADMITTED'],
};
const target: Record<ModuleOperation, ModuleState> = {
  INSTALL: 'INSTALLED_DISABLED',
  ENABLE: 'ENABLED',
  DISABLE: 'INSTALLED_DISABLED',
  UPGRADE: 'ENABLED',
  DOWNGRADE: 'ENABLED',
  ROLLBACK: 'ENABLED',
  UNINSTALL: 'REMOVED',
  RESOLVE: 'ADMITTED',
};

export function transitionModule(
  current: ModuleAggregate,
  operation: ModuleOperation,
  targetManifestDigest: string,
  preflight: ModulePreflight,
): ModuleAggregate {
  if (
    !allowed[operation].includes(current.state) ||
    current.aggregateVersion !== preflight.expectedVersion
  )
    throw new ContractError('PC-MODULE-7009');
  if (
    current.authorityEpoch !== preflight.authorityEpoch ||
    current.delegationEpoch !== preflight.delegationEpoch ||
    !preflight.approvalValid ||
    !preflight.distinctChecker ||
    !preflight.simulationSuccessful
  )
    throw new ContractError('PC-POLICY-2004');
  if (!preflight.supplyChainValid) throw new ContractError('PC-MODULE-7008');
  if (!preflight.dependencyClosed) throw new ContractError('PC-MODULE-7001');
  if (
    ['DISABLE', 'DOWNGRADE', 'ROLLBACK', 'UNINSTALL'].includes(operation) &&
    preflight.activeDependents > 0
  )
    throw new ContractError('PC-MODULE-7005');
  if (operation === 'UNINSTALL' && !preflight.custodyClosed)
    throw new ContractError('PC-MODULE-7006');
  return Object.freeze({
    ...current,
    state: target[operation],
    manifestDigest: targetManifestDigest,
    aggregateVersion: current.aggregateVersion + 1n,
  });
}
