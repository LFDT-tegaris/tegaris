import { describe, expect, it, vi } from 'vitest';

import { deriveOperationState, OperationRepository } from './operations.js';
import { managementDeploymentState } from '../deployment/result-readback.js';
import type { ReadContext } from '../persistence/scoped-read.js';
import type { OperationRecord } from '../persistence/types.js';
import { policyAuthoritySelectionSql } from '../../../../identity-service/src/db/policy-authority-selection.js';

function currentAuthority(bound: ReadContext['authorization']) {
  return {
    participantEpoch: bound.participantEpoch,
    principalEpoch: bound.principalEpoch,
    assignmentId: bound.assignmentId,
    assignmentRowVersion: bound.assignmentEpoch,
    authorityEnvelopeId: bound.authorityEnvelopeId,
    authorityEpoch: bound.authorityEpoch,
    delegationEpoch: bound.delegationEpoch,
    sessionEpoch: bound.sessionEpoch,
  };
}

describe('operation lifecycle projection', () => {
  it('uses the Fact owner for an authorized Fact proposal and preserves Control and missing-operation behavior', async () => {
    const context: ReadContext = {
      authorization: {
        participantId: '018f0000-0000-7000-8000-000000000101',
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        principalId: '018f0000-0000-7000-8000-000000000301',
        sessionId: '018f0000-0000-7000-8000-000000000302',
        sessionEpoch: '1',
        participantEpoch: '1',
        principalEpoch: '1',
        assignmentId: '018f0000-0000-7000-8000-000000000303',
        assignmentEpoch: '1',
        authorityEnvelopeId: '018f0000-0000-7000-8000-000000000304',
        authorityEpoch: '1',
        delegationEpoch: '1',
      },
      actionIntentId: 'ACT-OPERATIONS_READ_OPERATION-V1',
      resourceType: 'operations',
      resourceId: '018f0000-0000-7000-8000-000000000401',
    };
    const fact: OperationRecord = {
      operationId: context.resourceId,
      resourceRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000501',
      actionIntentId: 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
      intentDigest: `sha256:${'ab'.repeat(32)}`,
      idempotencyKey: 'fact-operation-owner-0001',
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
      revision: '1',
      createdAt: '2026-01-01T00:00:00.000000Z',
      updatedAt: '2026-01-01T00:00:00.000000Z',
    };
    let authorized = true;
    let current = true;
    let present = true;
    let actionIntentId = fact.actionIntentId;
    const client = {
      release: vi.fn(),
      query: vi.fn(async (sql: string) => {
        if (sql === policyAuthoritySelectionSql)
          return {
            rowCount: 1,
            rows: [
              { ...currentAuthority(context.authorization), authorityEpoch: current ? '1' : '2' },
            ],
          };
        if (sql.startsWith('select 1 from control.action_intent'))
          return { rowCount: authorized ? 1 : 0, rows: [] };
        if (sql.includes('from control.idempotency_record record') && present)
          return {
            rowCount: 1,
            rows: [
              {
                ...fact,
                actionIntentId,
                aggregateId: null,
                resultPayload: { resourceRef: fact.resourceRef },
                intentDigest: Buffer.alloc(32, 0xab),
                terminalState: 'COMMITTED',
                workState: actionIntentId === fact.actionIntentId ? 'COMPLETED' : null,
                resultReceiptDigest: null,
                lastErrorCode: null,
              },
            ],
          };
        return { rowCount: 0, rows: [] };
      }),
    };
    const repository = new OperationRepository({ connect: async () => client } as never);
    const owner = vi.fn(async () => fact);
    await expect(repository.get(context, owner)).resolves.toEqual(fact);
    expect(owner).toHaveBeenCalledOnce();
    expect(client.query).toHaveBeenCalledWith(policyAuthoritySelectionSql, [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.actionIntentId,
      context.resourceId,
      context.authorization.principalId,
      context.authorization.sessionId,
      false,
      false,
      false,
      null,
      null,
    ]);
    await expect(repository.get(context)).rejects.toMatchObject({ code: 'PC-INTEGRATION-5001' });
    owner.mockClear();
    actionIntentId = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
    await expect(repository.get(context, owner)).resolves.toMatchObject({
      actionIntentId,
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
    });
    expect(owner).not.toHaveBeenCalled();
    present = false;
    await expect(repository.get(context, owner)).resolves.toEqual(fact);
    await expect(repository.get(context)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
      statusOverride: 404,
    });
    owner.mockClear();
    authorized = false;
    await expect(repository.get(context, owner)).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(owner).not.toHaveBeenCalled();
    authorized = true;
    current = false;
    client.query.mockClear();
    await expect(repository.get(context, owner)).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(owner).not.toHaveBeenCalled();
    expect(
      client.query.mock.calls.some(([sql]) =>
        sql.includes('from control.idempotency_record record'),
      ),
    ).toBe(false);
  });
  it.each([
    ['CONFIRMED', 'SUCCESS', 'SUCCEEDED', 'SUCCESS'],
    ['CONFIRMED', 'UNKNOWN', 'WRITE_AMBIGUITY', 'WRITE_AMBIGUITY'],
    ['ACCEPTED', 'UNKNOWN', 'WRITE_AMBIGUITY', 'WRITE_AMBIGUITY'],
    ['REORG', 'REORG', 'FAILED', 'FAILED'],
    ['FAILED', 'UNAVAILABLE', 'FAILED', 'FAILED'],
    ['REJECTED', 'DENIED', 'FAILED', 'FAILED'],
  ])(
    'maps signed deployment %s/%s into the frozen management contract',
    (state, truthState, expectedState, expectedTruth) => {
      expect(managementDeploymentState({ state, truthState })).toEqual({
        state: expectedState,
        truthState: expectedTruth,
      });
    },
  );
  it('retains uncertainty after durable deployment handoff instead of reporting command commit as success', () => {
    expect(
      deriveOperationState({
        terminalState: 'COMMITTED',
        workState: null,
        resultReceiptDigest: null,
        lastErrorCode: null,
        deploymentHandoffState: 'HANDOFF',
        resultPayload: { state: 'ACCEPTED', truthState: 'UNKNOWN' },
      }),
    ).toEqual({ state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' });
  });
  it('retains accepted unknown for a committed asynchronous command without an execution result', () => {
    expect(
      deriveOperationState({
        terminalState: 'COMMITTED',
        workState: null,
        resultReceiptDigest: null,
        lastErrorCode: null,
        resultPayload: { state: 'ACCEPTED', truthState: 'UNKNOWN' },
      }),
    ).toEqual({ state: 'ACCEPTED', truthState: 'UNKNOWN' });
  });
  it.each([
    ['PENDING', null, null, 'ACCEPTED', 'UNKNOWN'],
    ['LEASED', null, null, 'RUNNING', 'UNKNOWN'],
    ['RECONCILING', null, 'PC-RUNTIME-3002', 'WRITE_AMBIGUITY', 'WRITE_AMBIGUITY'],
    ['COMPLETED', `sha256:${'a'.repeat(64)}`, null, 'SUCCEEDED', 'SUCCESS'],
    ['FAILED', `sha256:${'b'.repeat(64)}`, 'PC-FACT-4001', 'FAILED', 'FAILED'],
  ] as const)(
    'derives %s from the exact work state',
    (workState, resultReceiptDigest, lastErrorCode, state, truthState) => {
      expect(
        deriveOperationState({
          terminalState: 'COMMITTED',
          workState,
          resultReceiptDigest,
          lastErrorCode,
        }),
      ).toEqual({ state, truthState });
    },
  );

  it('rejects a terminal work claim without its required result fact', () => {
    expect(() =>
      deriveOperationState({
        terminalState: 'COMMITTED',
        workState: 'COMPLETED',
        resultReceiptDigest: null,
        lastErrorCode: null,
      }),
    ).toThrow('PC-FACT-4001');
    expect(() =>
      deriveOperationState({
        terminalState: 'COMMITTED',
        workState: 'FAILED',
        resultReceiptDigest: null,
        lastErrorCode: 'PC-FACT-4001',
      }),
    ).toThrow('PC-FACT-4001');
  });

  it('preserves ambiguous truth while a started effect is leased for read-only reconciliation', () => {
    expect(
      deriveOperationState({
        terminalState: 'COMMITTED',
        workState: 'LEASED',
        executionStartedAt: '2026-09-10T12:00:00.000000Z',
        resultReceiptDigest: null,
        lastErrorCode: 'PC-RUNTIME-3002',
      }),
    ).toEqual({ state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' });
  });

  it('reads a durable operation resource from its terminal idempotency payload without mutation evidence', async () => {
    const operationId = '018f0000-0000-7000-8000-000000000101';
    const resourceRef = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000201';
    const authorization: ReadContext['authorization'] = {
      sessionId: '018f0000-0000-7000-8000-000000000301',
      participantId: '018f0000-0000-7000-8000-000000000401',
      privacyDomainId: '018f0000-0000-7000-8000-000000000501',
      principalId: '018f0000-0000-7000-8000-000000000601',
      principalEpoch: '1',
      participantEpoch: '1',
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000000801',
      authorityEpoch: '1',
      delegationEpoch: '1',
      assignmentId: '018f0000-0000-7000-8000-000000000901',
      assignmentEpoch: '1',
    };
    const query = vi.fn(async (sql: string) => {
      if (sql === policyAuthoritySelectionSql)
        return { rowCount: 1, rows: [currentAuthority(authorization)] };
      if (sql.startsWith('select 1 from control.action_intent')) return { rowCount: 1, rows: [{}] };
      if (sql.includes('from control.idempotency_record record')) {
        return {
          rowCount: 1,
          rows: [
            {
              operationId,
              aggregateId: null,
              resultPayload: { resourceRef },
              actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
              intentDigest: Buffer.alloc(32, 0xab),
              idempotencyKey: 'public-approval-create-0001',
              terminalState: 'COMMITTED',
              workState: null,
              resultReceiptDigest: null,
              lastErrorCode: null,
              createdAt: '2026-01-01T00:00:00.000Z',
              updatedAt: '2026-01-01T00:00:00.000Z',
              revision: '1',
            },
          ],
        };
      }
      return { rowCount: 0, rows: [] };
    });
    const client = { query, release: vi.fn() };
    const repository = new OperationRepository({
      connect: vi.fn(async () => client),
    } as never);
    await expect(
      repository.get({
        authorization,
        actionIntentId: 'ACT-OPERATIONS_READ_OPERATION-V1',
        resourceType: 'operations',
        resourceId: operationId,
      }),
    ).resolves.toMatchObject({
      operationId,
      resourceRef,
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
      revision: '1',
    });
  });
});
