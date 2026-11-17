import {
  contractCounts,
  moduleIds,
  operationIds,
  stateIds,
  typeIds,
} from '../generated/contracts.js';

export type ModuleId = (typeof moduleIds)[number];
export type ModuleContractTypeId = (typeof typeIds)[number];
export type ModuleStateId = (typeof stateIds)[number];
export type ModuleOperationId = (typeof operationIds)[number];

export interface ModuleContractInventory {
  readonly moduleIds: readonly ModuleId[];
  readonly typeIds: readonly ModuleContractTypeId[];
  readonly stateIds: readonly ModuleStateId[];
  readonly operationIds: readonly ModuleOperationId[];
  readonly counts: typeof contractCounts;
}

export const frozenModuleContractInventory: ModuleContractInventory = Object.freeze({
  moduleIds,
  typeIds,
  stateIds,
  operationIds,
  counts: contractCounts,
});
