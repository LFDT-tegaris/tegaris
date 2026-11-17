import { describe, expect, it } from 'vitest';

import { controlMutationForAction } from './control-mutation-operations.js';

describe('shared control mutation catalog', () => {
  it('requires an explicit renewal binding while preserving direct initial activation', () => {
    const action = 'ACT-POLICY_ACTIVATE_RELEASE-V1';
    expect(controlMutationForAction(action)).toBeUndefined();
    expect(controlMutationForAction(action, 'LEGACY')).toBeUndefined();
    expect(controlMutationForAction(action, 'CFG-OP-RENEW-POLICY-ACTIVATION')).toMatchObject({
      actionIntentId: action,
      resourceType: 'release',
      operationClass: 'ACTIVATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(
      controlMutationForAction(
        'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
        'CFG-OP-RENEW-POLICY-ACTIVATION',
      ),
    ).toBeUndefined();
  });
  it('binds module DISABLE to the plural PATCH action without borrowing install or enable authority', () => {
    const action = 'ACT-MODULES_UPDATE_RESOURCE-V1';
    expect(controlMutationForAction(action, 'MOD-OP-DISABLE')).toEqual({
      catalogOperationId: 'MOD-OP-DISABLE',
      actionIntentId: action,
      resourceType: 'modules',
      operationClass: 'UPDATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
      aggregateType: 'module-registration',
    });
    for (const operation of ['MOD-OP-INSTALL', 'MOD-OP-ENABLE', 'MOD-OP-UNINSTALL'])
      expect(controlMutationForAction(action, operation)).toBeUndefined();
    for (const other of ['ACT-MODULE_CREATE_INSTALL-V1', 'ACT-MODULE_ACTIVATE_RESOURCE-V1'])
      expect(controlMutationForAction(other, 'MOD-OP-DISABLE')).toBeUndefined();
    expect(
      controlMutationForAction('ACT-MODULE_CREATE_INSTALL-V1', 'MOD-OP-INSTALL'),
    ).toMatchObject({ resourceType: 'module', operationClass: 'CREATE' });
    expect(
      controlMutationForAction('ACT-MODULE_ACTIVATE_RESOURCE-V1', 'MOD-OP-ENABLE'),
    ).toMatchObject({ resourceType: 'module', operationClass: 'ACTIVATE' });
  });
  it('keeps notification endpoint step-up and command namespaces distinct', () => {
    const expected = [
      [
        'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
        'CFG-OP-CREATE-NOTIFICATION-ENDPOINT',
        'notification-endpoints',
        true,
      ],
      [
        'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
        'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
        'notification-endpoints',
        true,
      ],
      [
        'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
        'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
        'notification-endpoint',
        false,
      ],
      [
        'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
        'CFG-OP-CREATE-NOTIFICATION',
        'notifications',
        false,
      ],
      [
        'ACT-NOTIFICATIONS_UPDATE_RESOURCE-V1',
        'CFG-OP-UPDATE-NOTIFICATION',
        'notifications',
        false,
      ],
      [
        'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
        'CFG-OP-ACKNOWLEDGE-NOTIFICATION',
        'notification',
        false,
      ],
    ] as const;
    for (const [action, operation, resourceType, stepUpRequired] of expected) {
      expect(controlMutationForAction(action, operation)).toMatchObject({
        resourceType,
        stepUpRequired,
        makerCheckerRequired: false,
      });
      for (const [, other] of expected)
        if (other !== operation) expect(controlMutationForAction(action, other)).toBeUndefined();
    }
  });
  it('binds policy-set drafting separately from activation authority', () => {
    expect(controlMutationForAction('ACT-POLICY_SETS_CREATE_RESOURCE-V1')).toEqual({
      catalogOperationId: 'CFG-OP-CREATE-POLICY-SET',
      actionIntentId: 'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
      resourceType: 'policy-sets',
      operationClass: 'CREATE',
      makerCheckerRequired: false,
      stepUpRequired: false,
      aggregateType: 'policy-set',
    });
    expect(
      controlMutationForAction(
        'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
        'CFG-OP-ACTIVATE-CIGL-PROFILES',
      ),
    ).toBeUndefined();
  });
  it('requires profile-specific approval and step-up for runtime profile activation', () => {
    expect(
      controlMutationForAction(
        'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
        'CFG-OP-ACTIVATE-CIGL-PROFILES',
      ),
    ).toMatchObject({
      resourceType: 'runtime-targets',
      operationClass: 'UPDATE',
      aggregateType: 'runtime-targets',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(
      controlMutationForAction(
        'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
        'CFG-OP-ACTIVATE-CIGL-PROFILES',
      ),
    ).toBeUndefined();
    expect(
      controlMutationForAction(
        'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
        'CFG-OP-UPDATE-RUNTIME-TARGET',
      ),
    ).toBeUndefined();
  });

  it('selects the exact Participant operation when action families share an intent', () => {
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ID-OP-ENVELOPE-CREATE'),
    ).toMatchObject({
      catalogOperationId: 'ID-OP-ENVELOPE-CREATE',
      resourceType: 'participant',
      operationClass: 'UPDATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ID-OP-DELEGATION-REVOKE'),
    ).toMatchObject({ catalogOperationId: 'ID-OP-DELEGATION-REVOKE', resourceType: 'participant' });
    expect(
      controlMutationForAction('ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ID-OP-ASSIGNMENT-CREATE'),
    ).toMatchObject({ catalogOperationId: 'ID-OP-ASSIGNMENT-CREATE', resourceType: 'principal' });
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ID-OP-PARTICIPANT-CREATE'),
    ).toBeUndefined();
  });

  it('selects the exact governed workload credential operation', () => {
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ID-OP-WORKLOAD-ISSUE'),
    ).toMatchObject({
      catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
      resourceType: 'participant',
      operationClass: 'UPDATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(
      controlMutationForAction('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1', 'ID-OP-WEBAUTHN-REGISTER'),
    ).toMatchObject({
      catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
      resourceType: 'participant',
      operationClass: 'UPDATE',
    });
  });
});
