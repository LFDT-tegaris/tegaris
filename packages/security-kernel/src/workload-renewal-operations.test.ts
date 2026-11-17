import { describe, expect, it } from 'vitest';
import { controlMutationForAction } from './control-mutation-operations.js';
import { identityMutationOperations } from './identity-mutation-operations.js';
import {
  workloadRenewalPolicyOperations,
  workloadRenewalRoutineBinding,
  workloadRenewalRoutineOperation,
  workloadInstanceAdmissionOperation,
} from './workload-renewal-operations.js';

describe('separate renewal authority catalog', () => {
  it('requires independent human governance for exact initial instance admission', () => {
    const operation = workloadInstanceAdmissionOperation;
    expect(
      controlMutationForAction(operation.actionIntentId, operation.catalogOperationId),
    ).toEqual({
      catalogOperationId: 'ID-OP-WORKLOAD-INSTANCE-ADMIT',
      command: 'ADMIT',
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceType: 'participant',
      operationClass: 'UPDATE',
      aggregateType: 'workload-instance-admission',
      authorizationMode: 'HUMAN_GOVERNED',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(
      controlMutationForAction(
        'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1',
        operation.catalogOperationId,
      ),
    ).toBeUndefined();
    expect(controlMutationForAction(operation.actionIntentId)).not.toEqual(operation);
    expect(
      workloadRenewalRoutineBinding(
        operation.actionIntentId,
        operation.catalogOperationId,
        workloadRenewalRoutineOperation.authorizationProfileId,
      ),
    ).toBeUndefined();
    expect(
      identityMutationOperations.some(
        (item) => item.catalogOperationId === (operation.catalogOperationId as string),
      ),
    ).toBe(false);
  });
  it('selects every human policy command only by its exact governed operation', () => {
    for (const operation of workloadRenewalPolicyOperations) {
      expect(
        controlMutationForAction(operation.actionIntentId, operation.catalogOperationId),
      ).toEqual(operation);
      expect(operation).toMatchObject({
        makerCheckerRequired: true,
        stepUpRequired: true,
        authorizationMode: 'HUMAN_GOVERNED',
      });
      expect(
        controlMutationForAction(
          'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          operation.catalogOperationId,
        ),
      ).toBeUndefined();
    }
  });
  it('cannot select routine renewal from the human factory or missing checker fallback', () => {
    const routine = workloadRenewalRoutineOperation;
    expect(
      controlMutationForAction(routine.actionIntentId, routine.catalogOperationId),
    ).toBeUndefined();
    expect(controlMutationForAction(routine.actionIntentId)).toBeUndefined();
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', routine.catalogOperationId),
    ).toBeUndefined();
    expect(
      identityMutationOperations.find(
        (item) => item.catalogOperationId === (routine.catalogOperationId as string),
      ),
    ).toBeUndefined();
  });
  it('requires the exact action, operation and policy authorization profile', () => {
    const r = workloadRenewalRoutineOperation;
    expect(
      workloadRenewalRoutineBinding(
        r.actionIntentId,
        r.catalogOperationId,
        r.authorizationProfileId,
      ),
    ).toEqual(r);
    for (const binding of [
      ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', r.catalogOperationId, r.authorizationProfileId],
      [r.actionIntentId, 'ID-OP-WORKLOAD-ROTATE', r.authorizationProfileId],
      [r.actionIntentId, r.catalogOperationId, 'pc.control.signing-rotation.advance'],
      [r.actionIntentId, r.catalogOperationId, ''],
    ])
      expect(workloadRenewalRoutineBinding(binding[0]!, binding[1]!, binding[2]!)).toBeUndefined();
  });
  it('preserves mandatory humans for the original manual credential operations', () => {
    for (const id of ['ID-OP-WORKLOAD-ISSUE', 'ID-OP-WORKLOAD-ROTATE', 'ID-OP-WORKLOAD-REVOKE'])
      expect(controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', id)).toMatchObject({
        makerCheckerRequired: true,
        stepUpRequired: true,
        aggregateType: 'identity',
      });
  });
});
