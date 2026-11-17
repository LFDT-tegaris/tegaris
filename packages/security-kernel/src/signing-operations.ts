/** Public AF-25 projection; these bindings are also consumed by the control migration generator. */
export const signingRotationActions = Object.freeze({
  create: 'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1',
  list: 'ACT-SIGNING_KEY_ROTATIONS_READ_COLLECTION-V1',
  read: 'ACT-SIGNING_KEY_ROTATIONS_READ_RESOURCE-V1',
  advance: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
  recover: 'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1',
  history: 'ACT-SIGNING_KEYS_READ_COLLECTION-V1',
});
export const signingRotationOperations = [
  {
    catalogOperationId: 'OPS-OP-CREATE-SIGNING-KEY-ROTATION',
    actionIntentId: signingRotationActions.create,
    method: 'POST',
    path: '/api/v1/signing-key-rotations',
    operationClass: 'CREATE',
    resourceType: 'signing-key-rotation',
    makerCheckerRequired: true,
  },
  {
    catalogOperationId: 'OPS-OP-LIST-SIGNING-KEY-ROTATIONS',
    actionIntentId: signingRotationActions.list,
    method: 'GET',
    path: '/api/v1/signing-key-rotations',
    operationClass: 'READ',
    resourceType: 'signing-key-rotation',
    makerCheckerRequired: false,
  },
  {
    catalogOperationId: 'OPS-OP-READ-SIGNING-KEY-ROTATION',
    actionIntentId: signingRotationActions.read,
    method: 'GET',
    path: '/api/v1/signing-key-rotations/{rotationId}',
    operationClass: 'READ',
    resourceType: 'signing-key-rotation',
    makerCheckerRequired: false,
  },
  {
    catalogOperationId: 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
    actionIntentId: signingRotationActions.advance,
    method: 'POST',
    path: '/api/v1/signing-key-rotations/{rotationId}/advance',
    operationClass: 'UPDATE',
    resourceType: 'signing-key-rotation',
    makerCheckerRequired: false,
  },
  {
    catalogOperationId: 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION',
    actionIntentId: signingRotationActions.recover,
    method: 'POST',
    path: '/api/v1/signing-key-rotations/{rotationId}/recover',
    operationClass: 'RECOVER',
    resourceType: 'signing-key-rotation',
    makerCheckerRequired: false,
  },
  {
    catalogOperationId: 'OPS-OP-LIST-SIGNING-KEYS',
    actionIntentId: signingRotationActions.history,
    method: 'GET',
    path: '/api/v1/signing-keys',
    operationClass: 'READ',
    resourceType: 'signing-key',
    makerCheckerRequired: false,
  },
] as const;
for (const operation of signingRotationOperations) Object.freeze(operation);
Object.freeze(signingRotationOperations);

/** The sole catalog for candidate-bearing signing commands. Read operations cannot acquire approvals. */
export const signingRotationCandidateOperations = Object.freeze(
  signingRotationOperations.filter((operation) => operation.method === 'POST'),
);
export function signingRotationCandidateOperation(actionIntentId: string) {
  const operation = signingRotationCandidateOperations.find(
    (operation) => operation.actionIntentId === actionIntentId,
  );
  if (!operation) throw new Error('Unsupported signing candidate action');
  return operation;
}
