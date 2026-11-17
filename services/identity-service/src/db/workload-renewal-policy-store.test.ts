import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import {
  businessTransitionProfileForOperation,
  workloadRenewalPolicyOperations,
  signingRoleProfiles,
} from '@openpc/security-kernel';
import { workloadRenewalPolicyDefinitionDigest } from '../contracts/workload-renewal-policy.js';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import {
  assertWorkloadRenewalPolicyTransition,
  bindWorkloadRenewalPolicyState,
  WorkloadRenewalPolicyRepository,
  type WorkloadRenewalPolicyState,
} from './workload-renewal-policy-store.js';
import { workloadRenewalPolicyGuardsSql } from './workload-renewal-policy-guards.mjs';
import { verifyConditionCases, verifyFunctionGrants } from './function-grants.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const definition = {
  version: 1 as const,
  participantId: id(1),
  privacyDomainId: id(2),
  policyId: id(3),
  principalId: id(4),
  workloadId: `urn:openpc:workload:${id(4)}`,
  issuerProfileDigest: `sha256:${'11'.repeat(32)}`,
  providerQualificationDigest: `sha256:${'22'.repeat(32)}`,
  attestationProfileDigest: `sha256:${'33'.repeat(32)}`,
  managedAttestorScopeDigest: `sha256:${'44'.repeat(32)}`,
  maximumInstances: 10,
  maximumEnrollmentsPerMinute: 3,
  certificateLifetimeSeconds: 3600,
  recoveryReserveSeconds: 300,
  maximumOverlapSeconds: 30,
  validFrom: '2026-10-04T00:00:00.000Z',
  validUntil: '2026-10-05T00:00:00.000Z',
};
const context: MutationContext = {
  authorization: {
    evidenceKind: 'USER_WEBAUTHN',
    participantId: id(1),
    privacyDomainId: id(2),
    principalId: id(5),
    signerCredentialId: id(6),
    sessionId: id(7),
    sessionEpoch: '1',
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: id(8),
    assignmentEpoch: '1',
    authorityEnvelopeId: id(9),
    authorityEpoch: '1',
    delegationEpoch: '0',
    evidenceCbor: Buffer.alloc(0),
    evidenceDigest: Buffer.alloc(32),
    coseSign1: Buffer.alloc(0),
  },
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'55'.repeat(32)}`,
  catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE',
  resourceType: 'participant',
  operationClass: 'UPDATE',
  aggregateType: 'workload-renewal-policy',
  resourceId: id(3),
  expectedRevision: '0',
  idempotencyKey: 'original-policy-command',
  candidate: {
    requestId: id(10),
    expectedRevision: '0',
    definition,
    reason: 'Approved managed workload scope',
  },
};
const initial: WorkloadRenewalPolicyState = {
  revision: '1',
  definition,
  definitionDigest: workloadRenewalPolicyDefinitionDigest(definition),
  state: 'ACTIVE',
  governanceOperationId: id(11),
  businessAncestorsDigest: `sha256:${'66'.repeat(32)}`,
};
const next = (changes: Partial<WorkloadRenewalPolicyState> = {}) => ({
  ...initial,
  revision: '2',
  governanceOperationId: id(12),
  ...changes,
});

it.each(workloadRenewalPolicyOperations)(
  'registers the exact human receipt for $command',
  (operation) => {
    const profile = businessTransitionProfileForOperation(operation.catalogOperationId)!;
    expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
    expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
    expect(profile).toMatchObject({
      catalogOperationId: operation.catalogOperationId,
      actionIntentId: operation.actionIntentId,
      aggregateType: operation.aggregateType,
      resourceType: operation.resourceType,
      profileVersion: 1,
    });
    expect(
      JSON.parse(profile.definitionCanonicalJson).authority.evidence.map(
        (e: { kind: number }) => e.kind,
      ),
    ).toEqual([3, 4]);
  },
);
it('binds every actual parent and the durable current state in the typed projection', () => {
  const a = bindWorkloadRenewalPolicyState(context, initial);
  expect(a.reference.stateDigest.equals(createHash('sha256').update(a.preimage).digest())).toBe(
    true,
  );
  for (const state of [
    next({ state: 'SUSPENDED' }),
    { ...initial, businessAncestorsDigest: `sha256:${'77'.repeat(32)}` },
  ])
    expect(
      bindWorkloadRenewalPolicyState(context, state).reference.stateDigest.equals(
        a.reference.stateDigest,
      ),
    ).toBe(false);
  expect(bindWorkloadRenewalPolicyState(context, undefined).reference).toMatchObject({
    existence: 0,
    revision: 0n,
  });
  expect(() =>
    bindWorkloadRenewalPolicyState({ ...context, resourceId: id(20) }, initial),
  ).toThrow();
  expect(() =>
    bindWorkloadRenewalPolicyState(context, {
      ...initial,
      definitionDigest: `sha256:${'ff'.repeat(32)}`,
    }),
  ).toThrow();
});
it('accepts independently governed create, changed revision, suspension and terminal revocation', () => {
  assertWorkloadRenewalPolicyTransition('CREATE', '0', id(11), undefined, initial);
  const revised = { ...definition, maximumInstances: 9 };
  assertWorkloadRenewalPolicyTransition(
    'REVISE',
    '1',
    id(12),
    initial,
    next({ definition: revised, definitionDigest: workloadRenewalPolicyDefinitionDigest(revised) }),
  );
  assertWorkloadRenewalPolicyTransition(
    'SUSPEND',
    '1',
    id(12),
    initial,
    next({ state: 'SUSPENDED' }),
  );
  assertWorkloadRenewalPolicyTransition('REVOKE', '1', id(12), initial, next({ state: 'REVOKED' }));
  expect(initial.state).toBe('ACTIVE');
});
it('rejects replay as a new effect, stale revision, fabricated digest and every revoked resurrection', () => {
  expect(() =>
    assertWorkloadRenewalPolicyTransition('CREATE', '0', id(11), initial, initial),
  ).toThrow();
  expect(() =>
    assertWorkloadRenewalPolicyTransition(
      'REVOKE',
      '2',
      id(12),
      initial,
      next({ state: 'REVOKED' }),
    ),
  ).toThrow();
  expect(() =>
    assertWorkloadRenewalPolicyTransition('REVISE', '1', id(12), initial, next()),
  ).toThrow();
  expect(() =>
    assertWorkloadRenewalPolicyTransition(
      'SUSPEND',
      '1',
      id(12),
      initial,
      next({ state: 'SUSPENDED', definition: { ...definition, maximumInstances: 9 } }),
    ),
  ).toThrow();
  for (const command of ['CREATE', 'REVISE', 'SUSPEND', 'REVOKE'] as const)
    expect(() =>
      assertWorkloadRenewalPolicyTransition(
        command,
        '1',
        id(12),
        { ...initial, state: 'REVOKED' },
        next(),
      ),
    ).toThrow();
  expect(() =>
    assertWorkloadRenewalPolicyTransition(
      'SUSPEND',
      '1',
      id(12),
      { ...initial, state: 'SUSPENDED' },
      next({ state: 'SUSPENDED' }),
    ),
  ).toThrow();
});
it('rejects wrong actor, scope, catalogue and absent signer before opening a transaction', async () => {
  const connect = vi.fn();
  const pool = { connect } as unknown as Pool;
  const signer = { environmentId: 'unit-boundary', signer: {} } as never;
  const repository = new WorkloadRenewalPolicyRepository(pool, signer);
  for (const input of [
    { ...context, catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-ADMIT' },
    { ...context, authorization: { ...context.authorization, participantId: id(30) } },
    { ...context, actionIntentId: 'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1' },
    { ...context, authorization: { ...context.authorization, evidenceKind: 'IDENTITY_RUNTIME' } },
  ])
    await expect(repository.execute(input as MutationContext)).rejects.toThrow();
  await expect(
    new WorkloadRenewalPolicyRepository(pool, undefined as never).execute(context),
  ).rejects.toThrow();
  expect(connect).not.toHaveBeenCalled();
});
it('keeps the SQL policy owner separate from routine and uses valid exact routine grants', () => {
  expect(() => verifyConditionCases(workloadRenewalPolicyGuardsSql)).not.toThrow();
  expect(() =>
    verifyFunctionGrants(workloadRenewalPolicyGuardsSql, workloadRenewalPolicyGuardsSql),
  ).not.toThrow();
});
