import { expect, it } from 'vitest';
import { controlMutationForAction } from './control-mutation-operations.js';
import { workloadSigningHandoverAdmissionOperation as operation } from './workload-signing-handover-operations.js';
import { signingRotationActions } from './signing-operations.js';

it('selects the explicit human-governed handover admission binding', () => {
  expect(controlMutationForAction(operation.actionIntentId, operation.catalogOperationId)).toEqual(
    operation,
  );
  expect(operation).toMatchObject({
    resourceType: 'workload-signing-handover',
    operationClass: 'ACTIVATE',
    makerCheckerRequired: true,
    stepUpRequired: true,
    authorizationMode: 'HUMAN_GOVERNED',
  });
});
it.each([
  undefined,
  'ID-OP-WORKLOAD-ROTATE',
  'OPS-OP-CREATE-SIGNING-KEY-ROTATION',
  'ID-OP-WORKLOAD-SIGNING-HANDOVER-OTHER',
])('rejects handover admission without its exact catalogue operation: %s', (catalogue) => {
  expect(controlMutationForAction(operation.actionIntentId, catalogue)).toBeUndefined();
});
it('does not substitute a legacy participant or preparation permission', () => {
  expect(
    controlMutationForAction(signingRotationActions.create, operation.catalogOperationId),
  ).toBeUndefined();
  expect(
    controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', operation.catalogOperationId),
  ).toBeUndefined();
});
