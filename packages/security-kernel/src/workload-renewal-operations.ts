/** Renewal-policy operations. Existing Identity catalog operations for manual
 * issue, rotate and revoke retain their human authority requirements. */
export const workloadRenewalPolicyOperations = Object.freeze(
  (
    [
      ['ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE', 'CREATE'],
      ['ID-OP-WORKLOAD-RENEWAL-POLICY-REVISE', 'REVISE'],
      ['ID-OP-WORKLOAD-RENEWAL-POLICY-SUSPEND', 'SUSPEND'],
      ['ID-OP-WORKLOAD-RENEWAL-POLICY-REVOKE', 'REVOKE'],
    ] as const
  ).map(([catalogOperationId, command]) =>
    Object.freeze({
      catalogOperationId,
      command,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceType: 'participant',
      operationClass: 'UPDATE',
      aggregateType: 'workload-renewal-policy',
      authorizationMode: 'HUMAN_GOVERNED',
      makerCheckerRequired: true,
      stepUpRequired: true,
    } as const),
  ),
);

/** Initial membership is a separate governed effect. Neither manual leaf
 * issuance nor policy creation is an instance-admission receipt. The installed
 * durable owner, independent witness and exact signing grant remain required. */
export const workloadInstanceAdmissionOperation = Object.freeze({
  catalogOperationId: 'ID-OP-WORKLOAD-INSTANCE-ADMIT',
  command: 'ADMIT',
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  resourceType: 'participant',
  operationClass: 'UPDATE',
  aggregateType: 'workload-instance-admission',
  authorizationMode: 'HUMAN_GOVERNED',
  makerCheckerRequired: true,
  stepUpRequired: true,
} as const);

/** This binding is deliberately absent from controlMutationForAction and the
 * generic human candidate factory. It needs the dedicated policy authorizer. */
export const workloadRenewalRoutineOperation = Object.freeze({
  catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-ADMIT',
  actionIntentId: 'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1',
  resourceType: 'workload-credential-family',
  operationClass: 'RENEW',
  aggregateType: 'workload-renewal',
  authorizationMode: 'POLICY_AUTHORIZED',
  authorizationProfileId: 'pc.identity.workload-renewal.policy-authorization.v1',
  requestProfileId: 'pc.identity.workload-renewal.request.v1',
} as const);

/** No action-only, caller-mode, legacy-operation or profile fallback. This is
 * contract selection only; it does not authenticate a policy or authorize I/O. */
export function workloadRenewalRoutineBinding(
  actionIntentId: string,
  catalogOperationId: string,
  authorizationProfileId: string,
) {
  const operation = workloadRenewalRoutineOperation;
  return actionIntentId === operation.actionIntentId &&
    catalogOperationId === operation.catalogOperationId &&
    authorizationProfileId === operation.authorizationProfileId
    ? operation
    : undefined;
}
