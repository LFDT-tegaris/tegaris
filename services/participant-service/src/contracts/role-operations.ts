import { participantLifecycleOperations } from './participant-lifecycle.js';
import { groupOperations } from './group-operations.js';
import { directoryGroupOperations } from './directory-group-operations.js';
import { platformScopeOperations } from './platform-scope-operations.js';
import { operationDefaults, participantOperations, type OperationContract } from './catalog.js';

/** Additive R1 role owner; the frozen identity/Participant operation entries remain intact. */
export const roleOperations = [
  {
    id: 'ID-OP-ROLE-CREATE',
    requestType: 'Role',
    responseType: 'Role',
    stateMachine: 'ROLE',
    allowedFromStates: [],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ROLE-ARCHIVE',
    requestType: 'RoleArchive',
    responseType: 'RoleArchiveResult',
    stateMachine: 'ROLE',
    allowedFromStates: ['ACTIVE'],
    successStates: ['ARCHIVED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
] as const satisfies readonly OperationContract[];

export const participantGovernanceOperations = [
  ...participantOperations,
  ...participantLifecycleOperations,
  ...roleOperations,
  ...groupOperations,
  ...directoryGroupOperations,
  ...platformScopeOperations,
];
