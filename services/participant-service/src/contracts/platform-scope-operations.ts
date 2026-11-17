import { operationDefaults, type OperationContract } from './catalog.js';

/** Explicit product extension. A Platform ceiling replacement is neither a
 * Participant envelope rotation nor permission to widen a child delegation. */
export const platformScopeOperations = [
  {
    id: 'ID-OP-PLATFORM-SCOPE-PREPARE',
    requestType: 'PlatformScopeReplacementPreparation',
    responseType: 'PlatformScopeReplacement',
    stateMachine: 'PLATFORM_SCOPE_REPLACEMENT',
    allowedFromStates: [],
    successStates: ['WITHDRAWING'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-PLATFORM-SCOPE-COMMIT',
    requestType: 'PlatformScopeReplacementCommit',
    responseType: 'PlatformScopeReplacement',
    stateMachine: 'PLATFORM_SCOPE_REPLACEMENT',
    allowedFromStates: ['WITHDRAWING'],
    successStates: ['COMMITTED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
] as const satisfies readonly OperationContract[];
