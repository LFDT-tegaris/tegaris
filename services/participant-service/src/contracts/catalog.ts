export interface OperationContract {
  readonly id: string;
  readonly requestType: string;
  readonly responseType: string;
  readonly stateMachine: string;
  readonly allowedFromStates: readonly string[];
  readonly successStates: readonly string[];
  readonly actionIntentId: string;
  readonly resourceType: 'identity';
  readonly operationClass: 'CREATE' | 'UPDATE' | 'ACTIVATE';
  readonly authorization: 'EFFECTIVE_INTERSECTION_ONLY';
  readonly denial: 'TERMINAL_NON_LEAKING';
  readonly idempotency: 'EXACT_OPERATION_ID_AND_DIGEST';
  readonly webauthnStepUpRequired: boolean;
  readonly makerCheckerRequired: boolean;
}

export const participantContractTypes = [
  'Participant',
  'AuthorityEnvelope',
  'Assignment',
  'Delegation',
  'WalletBinding',
] as const;

export const operationDefaults = {
  resourceType: 'identity',
  authorization: 'EFFECTIVE_INTERSECTION_ONLY',
  denial: 'TERMINAL_NON_LEAKING',
  idempotency: 'EXACT_OPERATION_ID_AND_DIGEST',
} as const;

export const participantOperations = [
  ...(['ROTATE', 'REVOKE'] as const).map(
    (mutation) =>
      ({
        id: `ID-OP-PARTICIPANT-FIRST-ADMIN-${mutation}`,
        requestType: 'ParticipantBootstrapCustodyChange',
        responseType: 'ParticipantBootstrapCustody',
        stateMachine: 'PARTICIPANT',
        allowedFromStates: ['PROVISIONING'],
        successStates: ['PROVISIONING'],
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        operationClass: 'UPDATE',
        webauthnStepUpRequired: true,
        makerCheckerRequired: true,
        ...operationDefaults,
      }) as const,
  ),
  {
    id: 'ID-OP-PARTICIPANT-CREATE',
    requestType: 'Participant',
    responseType: 'Participant',
    stateMachine: 'PARTICIPANT',
    allowedFromStates: [],
    successStates: ['PROVISIONING'],
    actionIntentId: 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
    operationClass: 'CREATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-PARTICIPANT-ACTIVATE',
    requestType: 'Participant',
    responseType: 'Participant',
    stateMachine: 'PARTICIPANT',
    allowedFromStates: ['PROVISIONING'],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    operationClass: 'ACTIVATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ENVELOPE-CREATE',
    requestType: 'AuthorityEnvelope',
    responseType: 'AuthorityEnvelope',
    stateMachine: 'AUTHORITY_ENVELOPE',
    allowedFromStates: [],
    successStates: ['DRAFT'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ENVELOPE-ACTIVATE',
    requestType: 'AuthorityEnvelope',
    responseType: 'AuthorityEnvelope',
    stateMachine: 'AUTHORITY_ENVELOPE',
    allowedFromStates: ['APPROVED'],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    operationClass: 'ACTIVATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ENVELOPE-REVOKE',
    requestType: 'AuthorityEnvelopeRevocation',
    responseType: 'AuthorityEnvelope',
    stateMachine: 'AUTHORITY_ENVELOPE',
    allowedFromStates: ['ACTIVE'],
    successStates: ['REVOKED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ASSIGNMENT-CREATE',
    requestType: 'Assignment',
    responseType: 'Assignment',
    stateMachine: 'ASSIGNMENT',
    allowedFromStates: [],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    operationClass: 'CREATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-ASSIGNMENT-REVOKE',
    requestType: 'Assignment',
    responseType: 'RevocationRecord',
    stateMachine: 'ASSIGNMENT',
    allowedFromStates: ['ACTIVE', 'SUSPENDED'],
    successStates: ['REVOKED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-DELEGATION-ISSUE',
    requestType: 'Delegation',
    responseType: 'Delegation',
    stateMachine: 'DELEGATION',
    allowedFromStates: [],
    successStates: ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    operationClass: 'CREATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
  {
    id: 'ID-OP-DELEGATION-REVOKE',
    requestType: 'Delegation',
    responseType: 'RevocationRecord',
    stateMachine: 'DELEGATION',
    allowedFromStates: ['ACTIVE', 'SUSPENDED'],
    successStates: ['REVOKED'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    operationClass: 'UPDATE',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  },
] as const satisfies readonly OperationContract[];

export const participantStates = {
  PARTICIPANT: ['PROVISIONING', 'ACTIVE', 'SUSPENDED', 'TRANSFER_PENDING', 'REVOKED', 'OFFBOARDED'],
  AUTHORITY_ENVELOPE: ['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED'],
  ASSIGNMENT: ['PROPOSED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'],
  DELEGATION: ['PROPOSED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'],
  WALLET_BINDING: ['PROPOSED', 'ACTIVE', 'REVOKED', 'EXPIRED'],
} as const;

export const participantEvents = [
  ['ID-EVT-PARTICIPANT-EPOCH', 'openpc.identity.participant.epoch.advanced.v1'],
  ['ID-EVT-ASSIGNMENT-STATE', 'openpc.identity.assignment.state.changed.v1'],
  ['ID-EVT-DELEGATION-STATE', 'openpc.identity.delegation.state.changed.v1'],
] as const;
