import { afterAll, describe, expect, it } from 'vitest';

import { buildIdentityService } from '../../../services/identity-service/src/app.js';
import {
  identityContractTypes,
  identityErrors,
  identityEvents,
  identityOperations,
  identityStates,
} from '../../../services/identity-service/src/contracts/catalog.js';
import { buildParticipantService } from '../../../services/participant-service/src/app.js';
import {
  participantContractTypes,
  participantEvents,
  participantOperations,
  participantStates,
} from '../../../services/participant-service/src/contracts/catalog.js';

const identityApp = buildIdentityService();
const participantApp = buildParticipantService();

const expectedContractTypes = [
  'Principal',
  'Participant',
  'AuthorityEnvelope',
  'Assignment',
  'Delegation',
  'Session',
  'WorkloadCredential',
  'MfaEvidence',
  'RecoveryCase',
  'RevocationRecord',
  'WalletBinding',
  'AuthorityContext',
  'AuthorityEvaluation',
  'OidcAuthorization',
] as const;

const expectedOperationIds = [
  'ID-OP-PRINCIPAL-PROVISION',
  'ID-OP-PRINCIPAL-SUSPEND',
  'ID-OP-PARTICIPANT-CREATE',
  'ID-OP-PARTICIPANT-ACTIVATE',
  'ID-OP-ENVELOPE-CREATE',
  'ID-OP-ENVELOPE-ACTIVATE',
  'ID-OP-ASSIGNMENT-CREATE',
  'ID-OP-ASSIGNMENT-REVOKE',
  'ID-OP-DELEGATION-ISSUE',
  'ID-OP-DELEGATION-REVOKE',
  'ID-OP-AUTH-EVALUATE',
  'ID-OP-OIDC-BEGIN',
  'ID-OP-OIDC-CALLBACK',
  'ID-OP-SESSION-REFRESH',
  'ID-OP-SESSION-REVOKE',
  'ID-OP-WEBAUTHN-REGISTER',
  'ID-OP-WEBAUTHN-VERIFY',
  'ID-OP-WORKLOAD-ISSUE',
  'ID-OP-WORKLOAD-ROTATE',
  'ID-OP-WORKLOAD-REVOKE',
  'ID-OP-RECOVERY-BEGIN',
  'ID-OP-RECOVERY-APPROVE',
  'ID-OP-RECOVERY-COMPLETE',
] as const;

const expectedStates = {
  PRINCIPAL: ['PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'OFFBOARDED'],
  PARTICIPANT: ['PROVISIONING', 'ACTIVE', 'SUSPENDED', 'TRANSFER_PENDING', 'REVOKED', 'OFFBOARDED'],
  AUTHORITY_ENVELOPE: ['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED'],
  ASSIGNMENT: ['PROPOSED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'],
  DELEGATION: ['PROPOSED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'],
  SESSION: ['AUTHENTICATING', 'ACTIVE', 'STEP_UP_REQUIRED', 'REVOKED', 'EXPIRED', 'COMPROMISED'],
  WORKLOAD_CREDENTIAL: ['ISSUED', 'ACTIVE', 'ROTATING', 'REVOKED', 'EXPIRED'],
  MFA_EVIDENCE: ['CHALLENGE_ISSUED', 'VERIFIED', 'CONSUMED', 'EXPIRED', 'REVOKED'],
  RECOVERY_CASE: [
    'REQUESTED',
    'CUSTODIAN_ONE_APPROVED',
    'CUSTODIAN_TWO_APPROVED',
    'LEASE_ACTIVE',
    'COMPLETED',
    'DENIED',
    'EXPIRED',
    'REVOKED',
  ],
  REVOCATION_RECORD: ['REQUESTED', 'COMMITTED', 'EVIDENCED'],
  WALLET_BINDING: ['PROPOSED', 'ACTIVE', 'REVOKED', 'EXPIRED'],
} as const;

const expectedErrorIds = [
  'PC-AUTH-0001',
  'PC-AUTH-0002',
  'PC-AUTH-0003',
  'PC-AUTH-0004',
  'PC-AUTH-0005',
  'PC-AUTH-0006',
  'PC-IDENTITY-1000',
  'PC-IDENTITY-1001',
  'PC-IDENTITY-1002',
  'PC-IDENTITY-1003',
  'PC-IDENTITY-1004',
  'PC-IDENTITY-1005',
  'PC-IDENTITY-1006',
  'PC-IDENTITY-1007',
  'PC-IDENTITY-1008',
  'PC-IDENTITY-1009',
] as const;

const expectedEventIds = [
  'ID-EVT-PRINCIPAL-STATE',
  'ID-EVT-PARTICIPANT-EPOCH',
  'ID-EVT-ASSIGNMENT-STATE',
  'ID-EVT-DELEGATION-STATE',
  'ID-EVT-SESSION-STATE',
  'ID-EVT-CREDENTIAL-STATE',
  'ID-EVT-RECOVERY-STATE',
  'ID-EVT-REVOCATION',
] as const;

afterAll(async () => {
  await Promise.all([identityApp.close(), participantApp.close()]);
});

describe('I02 frozen contract denominator', () => {
  it('exposes exactly 14 types, 23 operations, 58 states, 16 errors, and 8 events', () => {
    const contractTypes = [...identityContractTypes, ...participantContractTypes];
    const operations = [...identityOperations, ...participantOperations];
    const stateCount = [
      ...Object.values(identityStates),
      ...Object.values(participantStates),
    ].reduce((total, states) => total + states.length, 0);
    const events = [...identityEvents, ...participantEvents];

    expect(contractTypes).toHaveLength(14);
    expect(new Set(contractTypes)).toHaveLength(14);
    expect(operations).toHaveLength(23);
    expect(new Set(operations.map(({ id }) => id))).toHaveLength(23);
    expect(stateCount).toBe(58);
    expect(identityErrors).toHaveLength(16);
    expect(new Set(identityErrors.map(([id]) => id))).toHaveLength(16);
    expect(events).toHaveLength(8);
    expect(new Set(events.map(([id]) => id))).toHaveLength(8);

    expect(new Set(contractTypes)).toEqual(new Set(expectedContractTypes));
    expect(new Set(operations.map(({ id }) => id))).toEqual(new Set(expectedOperationIds));
    expect({ ...identityStates, ...participantStates }).toEqual(expectedStates);
    expect(identityErrors.map(([id]) => id)).toEqual(expectedErrorIds);
    expect(new Set(events.map(([id]) => id))).toEqual(new Set(expectedEventIds));
  });

  it('serves each service-owned catalog without mutation', async () => {
    const [identityResponse, participantResponse] = await Promise.all([
      identityApp.inject({ method: 'GET', url: '/v1/identity/contracts' }),
      participantApp.inject({ method: 'GET', url: '/v1/participants/contracts' }),
    ]);

    expect(identityResponse.statusCode).toBe(200);
    expect(participantResponse.statusCode).toBe(200);
    expect(identityResponse.json()).toEqual({
      contractTypes: identityContractTypes,
      operations: identityOperations,
      states: identityStates,
      errors: identityErrors,
      events: identityEvents,
    });
    expect(participantResponse.json()).toEqual({
      contractTypes: participantContractTypes,
      operations: participantOperations,
      states: participantStates,
      events: participantEvents,
    });
  });

  it('makes every operation fail closed at the contract boundary', () => {
    for (const operation of [...identityOperations, ...participantOperations]) {
      expect(operation.authorization).toBe('EFFECTIVE_INTERSECTION_ONLY');
      expect(operation.denial).toBe('TERMINAL_NON_LEAKING');
      expect(operation.idempotency).toBe('EXACT_OPERATION_ID_AND_DIGEST');
      expect(operation.actionIntentId).toMatch(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u);
    }
  });

  it('pins every participant operation to its exact intent and state transition', async () => {
    expect(
      participantOperations.map(
        ({ id, actionIntentId, stateMachine, allowedFromStates, successStates }) => ({
          id,
          actionIntentId,
          stateMachine,
          allowedFromStates,
          successStates,
        }),
      ),
    ).toEqual([
      {
        id: 'ID-OP-PARTICIPANT-CREATE',
        actionIntentId: 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
        stateMachine: 'PARTICIPANT',
        allowedFromStates: [],
        successStates: ['PROVISIONING'],
      },
      {
        id: 'ID-OP-PARTICIPANT-ACTIVATE',
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        stateMachine: 'PARTICIPANT',
        allowedFromStates: ['PROVISIONING'],
        successStates: ['ACTIVE'],
      },
      {
        id: 'ID-OP-ENVELOPE-CREATE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        stateMachine: 'AUTHORITY_ENVELOPE',
        allowedFromStates: [],
        successStates: ['DRAFT'],
      },
      {
        id: 'ID-OP-ENVELOPE-ACTIVATE',
        actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        stateMachine: 'AUTHORITY_ENVELOPE',
        allowedFromStates: ['APPROVED'],
        successStates: ['ACTIVE'],
      },
      {
        id: 'ID-OP-ASSIGNMENT-CREATE',
        actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
        stateMachine: 'ASSIGNMENT',
        allowedFromStates: [],
        successStates: ['ACTIVE'],
      },
      {
        id: 'ID-OP-ASSIGNMENT-REVOKE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        stateMachine: 'ASSIGNMENT',
        allowedFromStates: ['ACTIVE', 'SUSPENDED'],
        successStates: ['REVOKED'],
      },
      {
        id: 'ID-OP-DELEGATION-ISSUE',
        actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
        stateMachine: 'DELEGATION',
        allowedFromStates: [],
        successStates: ['ACTIVE'],
      },
      {
        id: 'ID-OP-DELEGATION-REVOKE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        stateMachine: 'DELEGATION',
        allowedFromStates: ['ACTIVE', 'SUSPENDED'],
        successStates: ['REVOKED'],
      },
    ]);

    const [suspend, approve] = await Promise.all([
      participantApp.inject({ method: 'POST', url: '/v1/participants/unused/suspend' }),
      participantApp.inject({
        method: 'POST',
        url: '/v1/participants/unused/envelopes/unused/approve',
      }),
    ]);
    expect(suspend.statusCode).toBe(404);
    expect(approve.statusCode).toBe(404);
  });
});
