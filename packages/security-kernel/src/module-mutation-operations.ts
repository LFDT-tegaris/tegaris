/** Implementation binding for the frozen createModule action; registration never enables a module. */
export const moduleRegistrationOperation = Object.freeze({
  catalogOperationId: 'MOD-OP-REGISTER',
  actionIntentId: 'ACT-MODULES_CREATE_RESOURCE-V1',
  resourceType: 'modules',
  operationClass: 'CREATE',
  makerCheckerRequired: true,
  stepUpRequired: true,
  aggregateType: 'module-registration',
} as const);

/** Frozen install/activate actions use singular module; PATCH uses plural modules. */
export const moduleLifecycleOperations = (
  [
    {
      catalogOperationId: 'MOD-OP-INSTALL',
      actionIntentId: 'ACT-MODULE_CREATE_INSTALL-V1',
      resourceType: 'module',
      operationClass: 'CREATE',
    },
    {
      catalogOperationId: 'MOD-OP-ENABLE',
      actionIntentId: 'ACT-MODULE_ACTIVATE_RESOURCE-V1',
      resourceType: 'module',
      operationClass: 'ACTIVATE',
    },
    {
      catalogOperationId: 'MOD-OP-DISABLE',
      actionIntentId: 'ACT-MODULES_UPDATE_RESOURCE-V1',
      resourceType: 'modules',
      operationClass: 'UPDATE',
    },
  ] as const
).map((operation) =>
  Object.freeze({
    ...operation,
    makerCheckerRequired: true,
    stepUpRequired: true,
    aggregateType: 'module-registration',
  } as const),
);

export type ModuleMutationOperationId =
  | typeof moduleRegistrationOperation.catalogOperationId
  | (typeof moduleLifecycleOperations)[number]['catalogOperationId'];

export function moduleMutationOperation(catalogOperationId: string) {
  return [moduleRegistrationOperation, ...moduleLifecycleOperations].find(
    (operation) => operation.catalogOperationId === catalogOperationId,
  );
}
