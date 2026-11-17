import { operationDefaults, type OperationContract } from './catalog.js';

export const recoveryOperations = [
  {
    id: 'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
    requestType: 'RecoveryPrincipalQualification',
    responseType: 'Principal',
    stateMachine: 'RECOVERY_PRINCIPAL',
    allowedFromStates: [],
    successStates: ['ACTIVE'],
  },
  {
    id: 'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
    requestType: 'RecoveryPrincipalRevocation',
    responseType: 'Principal',
    stateMachine: 'RECOVERY_PRINCIPAL',
    allowedFromStates: ['ACTIVE'],
    successStates: ['REVOKED'],
  },
  {
    id: 'ID-OP-RECOVERY-POST-REVIEW',
    requestType: 'RecoveryPostReview',
    responseType: 'RecoveryCase',
    stateMachine: 'RECOVERY',
    allowedFromStates: ['COMPLETED'],
    successStates: ['COMPLETED'],
  },
].map((operation) => ({
  ...operation,
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  webauthnStepUpRequired: true,
  makerCheckerRequired: true,
  ...operationDefaults,
})) satisfies readonly OperationContract[];
