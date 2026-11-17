import {
  moduleRegistrationOperation,
  moduleLifecycleOperations,
} from './module-mutation-operations.js';
import { configurationMutationForAction } from './configuration-operations.js';
import { signingRotationOperations } from './signing-operations.js';
import { workloadSigningHandoverAdmissionOperation } from './workload-signing-handover-operations.js';
import { participantMutationOperations } from './participant-mutation-operations.js';
import { identityMutationOperations } from './identity-mutation-operations.js';
import {
  workloadRenewalPolicyOperations,
  workloadInstanceAdmissionOperation,
} from './workload-renewal-operations.js';

/** Closed mutation bindings shared by the identity assertion owner and supported control owners. */
export function controlMutationForAction(actionIntentId: string, catalogOperationId?: string) {
  if (
    actionIntentId === workloadSigningHandoverAdmissionOperation.actionIntentId &&
    catalogOperationId === workloadSigningHandoverAdmissionOperation.catalogOperationId
  )
    return workloadSigningHandoverAdmissionOperation;
  const moduleLifecycle = moduleLifecycleOperations.find(
    (operation) =>
      operation.actionIntentId === actionIntentId &&
      (catalogOperationId === undefined || operation.catalogOperationId === catalogOperationId),
  );
  if (moduleLifecycle !== undefined) return moduleLifecycle;
  if (
    actionIntentId === moduleRegistrationOperation.actionIntentId &&
    (catalogOperationId === undefined ||
      catalogOperationId === moduleRegistrationOperation.catalogOperationId)
  )
    return moduleRegistrationOperation;
  const configuration = configurationMutationForAction(actionIntentId);
  if (
    configuration !== undefined &&
    // Governed renewal is explicit. Preserve the existing direct initial-
    // activation audience when no renewal catalogue operation was requested.
    (configuration.catalogOperationId !== 'CFG-OP-RENEW-POLICY-ACTIVATION' ||
      catalogOperationId === configuration.catalogOperationId) &&
    (catalogOperationId === undefined || configuration.catalogOperationId === catalogOperationId)
  )
    return configuration;
  const participant = participantMutationOperations.find(
    (operation) =>
      operation.actionIntentId === actionIntentId &&
      (catalogOperationId === undefined || operation.catalogOperationId === catalogOperationId),
  );
  if (participant !== undefined) return participant;
  const identity = identityMutationOperations.find(
    (operation) =>
      operation.actionIntentId === actionIntentId &&
      (catalogOperationId === undefined || operation.catalogOperationId === catalogOperationId),
  );
  if (identity !== undefined) return identity;
  // Renewal policy governance is explicit and cannot be inferred from the
  // participant action alone. Routine renewal never enters this human owner.
  const renewalPolicy = workloadRenewalPolicyOperations.find(
    (operation) =>
      operation.actionIntentId === actionIntentId &&
      operation.catalogOperationId === catalogOperationId,
  );
  if (renewalPolicy !== undefined) return renewalPolicy;
  if (
    actionIntentId === workloadInstanceAdmissionOperation.actionIntentId &&
    catalogOperationId === workloadInstanceAdmissionOperation.catalogOperationId
  )
    return workloadInstanceAdmissionOperation;
  const signing = signingRotationOperations.find(
    (operation) =>
      operation.actionIntentId === actionIntentId &&
      (operation.operationClass === 'UPDATE' || operation.operationClass === 'RECOVER'),
  );
  return signing === undefined
    ? undefined
    : { ...signing, stepUpRequired: false, aggregateType: 'signing-key-rotation' };
}
