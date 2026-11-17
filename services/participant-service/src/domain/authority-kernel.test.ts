import {
  envelopeFromGovernedCreation,
  envelopeFromRow,
  type EnvelopeRow,
} from './authority-records.js';
import { describe, expect, it } from 'vitest';

import {
  evaluateAuthority,
  validateDelegation,
  type Assignment,
  type AuthorityEnvelope,
  type Delegation,
} from './authority-kernel.js';
import { PostgresParticipantRepository } from './participant-kernel.js';

const participantId = 'urn:openpc:participant:018f1e2d-3c4b-7a69-8abc-0123456789ab';
const principalId = 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-1123456789ab';
const now = new Date('2026-08-28T00:00:00.000Z');
const scope = {
  participantId,
  privacyDomainIds: ['privacy-a'],
  actionIntentIds: ['ACT-PARTICIPANT_CREATE_MEMBER-V1'],
  resourceIds: ['resource-a'],
  riskClasses: ['HIGH'],
  validFrom: new Date('2026-08-27T00:00:00.000Z'),
  validUntil: new Date('2026-08-29T00:00:00.000Z'),
  makerCheckerRequired: true,
  stepUpRequired: true,
  onwardDelegationDepth: 2,
};

const envelope: AuthorityEnvelope = {
  id: 'envelope-a',
  authorityEpoch: '7',
  state: 'ACTIVE',
  semanticDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  ...scope,
};

const assignment: Assignment = {
  id: 'assignment-a',
  principalId,
  authorityEnvelopeId: envelope.id,
  state: 'ACTIVE',
  delegationEpoch: '3',
  scopeDigest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  ...scope,
};

function request(overrides: Partial<Parameters<typeof evaluateAuthority>[0]> = {}) {
  return {
    principalId,
    participantId,
    participantContextCount: 1,
    privacyDomainId: 'privacy-a',
    actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    resourceId: 'resource-a',
    riskClass: 'HIGH',
    participantEpoch: '7',
    principalEpoch: '11',
    authorityEpoch: '7',
    delegationEpoch: '3',
    currentParticipantEpoch: '7',
    currentPrincipalEpoch: '11',
    currentAuthorityEpoch: '7',
    platformPermits: true,
    policyAvailable: true,
    factsAvailable: true,
    factsTampered: false,
    existenceVisible: true,
    payloadVisible: true,
    stepUpFresh: true,
    makerPrincipalId: 'maker',
    checkerPrincipalId: 'checker',
    envelope,
    assignment,
    delegations: [],
    now,
    ...overrides,
  };
}

describe('authority kernel', () => {
  it('allows only the complete current effective intersection', () => {
    expect(evaluateAuthority(request())).toMatchObject({
      decision: 'ALLOW',
      authorized: true,
      terminal: false,
    });
  });

  it('treats a null validity end as unbounded without allowing a child to outlive a bounded parent', () => {
    const unboundedEnvelope = { ...envelope, validUntil: null };
    const unboundedAssignment = { ...assignment, validUntil: null };
    expect(
      evaluateAuthority(request({ envelope: unboundedEnvelope, assignment: unboundedAssignment })),
    ).toMatchObject({ decision: 'ALLOW', authorized: true });

    const child = {
      id: 'delegation-unbounded',
      parentId: assignment.id,
      grantorId: principalId,
      granteeId: 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-2123456789ab',
      state: 'ACTIVE',
      delegationEpoch: '3',
      scopeDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      ...scope,
      validUntil: null,
      onwardDelegationDepth: 1,
    } satisfies Delegation;
    expect(validateDelegation(child, assignment)).toBe('PC-IDENTITY-1003');
    expect(validateDelegation(child, { ...assignment, validUntil: null })).toBeUndefined();
  });

  it('honors the established all-resource wildcard without allowing a child wildcard to broaden a parent', () => {
    expect(
      evaluateAuthority(
        request({
          envelope: { ...envelope, resourceIds: ['*'] },
          assignment: { ...assignment, resourceIds: ['*'] },
        }),
      ),
    ).toMatchObject({ decision: 'ALLOW', authorized: true });

    const child = {
      id: 'delegation-wildcard',
      parentId: assignment.id,
      grantorId: principalId,
      granteeId: 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-2123456789ab',
      state: 'ACTIVE',
      delegationEpoch: '3',
      scopeDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      ...scope,
      resourceIds: ['*'],
      onwardDelegationDepth: 1,
    } satisfies Delegation;
    expect(validateDelegation(child, assignment)).toBe('PC-IDENTITY-1003');
    expect(validateDelegation(child, { ...assignment, resourceIds: ['*'] })).toBeUndefined();
  });

  it('fails closed for stale epochs, unavailable/tampered inputs, visibility and maker-checker collapse', () => {
    expect(evaluateAuthority(request({ authorityEpoch: '6' }))).toMatchObject({
      decision: 'STALE',
      errorCode: 'PC-IDENTITY-1001',
      authorized: false,
      existenceVisible: false,
    });
    expect(evaluateAuthority(request({ principalEpoch: '10' }))).toMatchObject({
      decision: 'STALE',
      errorCode: 'PC-IDENTITY-1001',
    });
    expect(evaluateAuthority(request({ participantContextCount: 2 }))).toMatchObject({
      decision: 'CONFLICT',
      errorCode: 'PC-IDENTITY-1000',
    });
    expect(evaluateAuthority(request({ policyAvailable: false }))).toMatchObject({
      decision: 'UNAVAILABLE',
      errorCode: 'PC-IDENTITY-1004',
    });
    expect(evaluateAuthority(request({ factsTampered: true }))).toMatchObject({
      decision: 'TAMPERED',
      errorCode: 'PC-IDENTITY-1004',
    });
    expect(evaluateAuthority(request({ payloadVisible: false }))).toMatchObject({
      decision: 'DENY',
      errorCode: 'PC-IDENTITY-1008',
      existenceVisible: false,
      payloadVisible: false,
    });
    expect(
      evaluateAuthority(
        request({ makerPrincipalId: principalId, checkerPrincipalId: principalId }),
      ),
    ).toMatchObject({ decision: 'CONFLICT', errorCode: 'PC-IDENTITY-1005' });
  });

  it('rejects a delegation that broadens scope, weakens step-up, crosses a participant, or self-delegates', () => {
    const child: Delegation = {
      id: 'delegation-a',
      parentId: assignment.id,
      grantorId: principalId,
      granteeId: 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-2123456789ab',
      state: 'ACTIVE',
      delegationEpoch: '3',
      scopeDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      ...scope,
      onwardDelegationDepth: 1,
    };
    expect(validateDelegation(child, assignment)).toBeUndefined();
    expect(validateDelegation({ ...child, grantorId: 'unrelated-principal' }, assignment)).toBe(
      'PC-IDENTITY-1003',
    );
    // A management grant cannot be widened into a runtime invocation grant.
    const runtimeChild: Delegation = { ...child, capabilityIds: ['CALL_RESULT_DISCLOSURE'] };
    expect(validateDelegation(runtimeChild, assignment)).toBe('PC-IDENTITY-1003');
    expect(
      validateDelegation(runtimeChild, {
        ...assignment,
        capabilityIds: ['CALL_RESULT_DISCLOSURE', 'GAS_ESTIMATE_DISCLOSURE'],
      }),
    ).toBeUndefined();
    expect(
      validateDelegation(
        { ...runtimeChild, capabilityIds: ['SIGNED_TRANSACTION_SUBMISSION'] },
        {
          ...assignment,
          capabilityIds: ['CALL_RESULT_DISCLOSURE'],
        },
      ),
    ).toBe('PC-IDENTITY-1003');
    expect(
      validateDelegation(
        { ...child, actionIntentIds: [...scope.actionIntentIds, 'ACT-EXTRA-V1'] },
        assignment,
      ),
    ).toBe('PC-IDENTITY-1003');
    expect(validateDelegation({ ...child, stepUpRequired: false }, assignment)).toBe(
      'PC-IDENTITY-1003',
    );
    expect(validateDelegation({ ...child, participantId: 'other' }, assignment)).toBe(
      'PC-IDENTITY-1003',
    );
    expect(validateDelegation({ ...child, granteeId: principalId }, assignment)).toBe(
      'PC-IDENTITY-1003',
    );
  });

  it('evaluates an ordered multi-hop delegation chain only for its terminal grantee', () => {
    const intermediary = 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-2123456789ab';
    const terminalPrincipal = 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-3123456789ab';
    const first: Delegation = {
      id: 'delegation-first',
      parentId: assignment.id,
      grantorId: principalId,
      granteeId: intermediary,
      state: 'ACTIVE',
      delegationEpoch: '3',
      scopeDigest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      ...scope,
      onwardDelegationDepth: 1,
    };
    const second: Delegation = {
      ...first,
      id: 'delegation-second',
      parentId: first.id,
      grantorId: intermediary,
      granteeId: terminalPrincipal,
      scopeDigest: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      onwardDelegationDepth: 0,
    };
    expect(
      evaluateAuthority(request({ principalId: terminalPrincipal, delegations: [first, second] })),
    ).toMatchObject({ decision: 'ALLOW', authorized: true });
    expect(
      evaluateAuthority(request({ principalId: intermediary, delegations: [first, second] })),
    ).toMatchObject({ decision: 'CONFLICT', errorCode: 'PC-IDENTITY-1003' });
  });

  it('rejects cross-participant revocation before any repository access', async () => {
    const repository = new PostgresParticipantRepository(undefined as never);
    await expect(
      repository.revokeAuthority(
        {
          principalId,
          participantId,
          boundParticipantEpoch: '7',
          boundPrincipalEpoch: '7',
          boundEnvelopeEpoch: '7',
          platform: false,
        },
        '018f1e2d-3c4b-7a69-8abc-0123456789ab',
        'assignment',
        '018f1e2d-3c4b-7a69-8abc-2123456789ab',
      ),
    ).rejects.toMatchObject({ code: 'PC-IDENTITY-1000' });
  });
});

it('projects handoff binding only from the exact authenticated creation and preserves unbound envelopes', () => {
  const row: EnvelopeRow = {
    authority_envelope_id: '018f0000-0000-7000-8000-000000000601',
    participant_id: '018f0000-0000-7000-8000-000000000101',
    privacy_domain_ids: ['018f0000-0000-7000-8000-000000000201'],
    action_intent_ids: [],
    resource_ids: [],
    risk_classes: [],
    maker_checker_required: true,
    step_up_required: true,
    onward_delegation_depth: 0,
    authority_epoch: '10',
    delegation_epoch: '0',
    state: 'DRAFT',
    row_version: '1',
    valid_from: new Date('2026-01-01T00:00:00Z'),
    valid_until: new Date('2027-01-01T00:00:00Z'),
    semantic_digest: Buffer.alloc(32, 1),
  };
  const creation = {
    envelopeId: row.authority_envelope_id,
    participantId: row.participant_id,
    platformScopeReplacementId: '018f0000-0000-7000-8000-000000000901',
  };
  expect(envelopeFromGovernedCreation(row, creation)).toEqual({
    ...envelopeFromRow(row),
    platformScopeReplacementId: creation.platformScopeReplacementId,
  });
  expect(
    envelopeFromGovernedCreation(row, {
      envelopeId: creation.envelopeId,
      participantId: creation.participantId,
    }),
  ).toEqual(envelopeFromRow(row));
  expect(() =>
    envelopeFromGovernedCreation(row, {
      ...creation,
      envelopeId: '018f0000-0000-7000-8000-000000000602',
    }),
  ).toThrow('identity mismatch');
  expect(() =>
    envelopeFromGovernedCreation(row, {
      ...creation,
      participantId: '018f0000-0000-7000-8000-000000000102',
    }),
  ).toThrow('identity mismatch');
  expect(envelopeFromRow(row)).not.toHaveProperty('platformScopeReplacementId');
});
