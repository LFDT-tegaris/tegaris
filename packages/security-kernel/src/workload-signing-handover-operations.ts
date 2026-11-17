/** Explicit handover admission permission. Registering this binding must never
 * extend a retained assignment, authority envelope or installation ceiling. */
export const workloadSigningHandoverAdmissionOperation = Object.freeze({
  catalogOperationId: 'ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT',
  actionIntentId: 'ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1',
  resourceType: 'workload-signing-handover',
  operationClass: 'ACTIVATE',
  aggregateType: 'workload-signing-handover',
  authorizationMode: 'HUMAN_GOVERNED',
  makerCheckerRequired: true,
  stepUpRequired: true,
  method: 'POST',
  path: '/api/v1/workload-signing-handovers/{handoverId}/admit',
} as const);
