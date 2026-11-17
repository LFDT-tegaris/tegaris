import { recoveryOperations } from './recovery-operations.js';
import { directoryOperations } from './directory-operations.js';
import { invitationOperations } from './invitation-operations.js';
import { walletBindingOperations } from './wallet-binding-operations.js';
import { identityOperations, operationDefaults, type OperationContract } from './catalog.js';

/** Additive lifecycle owner; preserved catalog entries keep their frozen semantics. */
export const principalOperations = [
  {
    id: 'ID-OP-MEMBERSHIP-REMOVE',
    requestType: 'MembershipRemoval',
    responseType: 'Principal',
    stateMachine: 'PRINCIPAL',
    allowedFromStates: ['PROVISIONED', 'ACTIVE', 'SUSPENDED'],
    successStates: ['OFFBOARDED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-PRINCIPAL-ACTIVATE',
    requestType: 'PrincipalActivation',
    responseType: 'Principal',
    stateMachine: 'PRINCIPAL',
    allowedFromStates: ['PROVISIONED'],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
] as const satisfies readonly OperationContract[];
export const identityGovernanceOperations = [
  ...identityOperations,
  ...principalOperations,
  ...recoveryOperations,
  ...directoryOperations,
  ...invitationOperations,
  ...walletBindingOperations,
];
