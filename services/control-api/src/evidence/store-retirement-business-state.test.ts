import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  businessTransitionProfileForOperation,
  configurationMutationOperation,
  signingRoleProfiles,
} from '@openpc/security-kernel';
import { decodeCbor } from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import { governedReceiptOperationIds } from '../../../identity-service/src/db/governed-receipt-inputs.js';
import type { MutationContext } from '../configuration/persistence/types.js';
import { bindStoreRetirementAdmission } from './store-retirement-business-state.js';

const uuid = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const context = {
  catalogOperationId: 'CFG-OP-ADMIT-STORE-RETIREMENT',
  resourceId: uuid(1),
  authorization: { participantId: uuid(2), privacyDomainId: uuid(3), approvalRequestId: uuid(4) },
} as MutationContext;
const state = {
  attemptId: uuid(1),
  retirementId: uuid(1),
  previousAttemptId: null,
  hostDigest: '01'.repeat(32),
  attemptDigest: '02'.repeat(32),
  selectionDigest: '03'.repeat(32),
  sourceBindingDigest: `sha256:${'04'.repeat(32)}`,
  retentionPolicyId: uuid(5),
  approvalRequestId: uuid(4),
  operationId: uuid(6),
  lifecycleRevision: '9007199254740993',
  dispatchNotAfterMs: '1800000060000',
  revision: '1' as const,
  admittedAtNs: '1800000000000000000',
};

it('connects the admission-only profile to independent approval, step-up, role and exact state fields', () => {
  const operation = configurationMutationOperation('CFG-OP-ADMIT-STORE-RETIREMENT');
  const profile = businessTransitionProfileForOperation(operation.catalogOperationId)!;
  const definition = JSON.parse(profile.definitionCanonicalJson);
  expect(operation).toMatchObject({
    aggregateType: 'store-retirement',
    makerCheckerRequired: true,
    stepUpRequired: true,
  });
  expect(profile.actionIntentId).toBe(operation.actionIntentId);
  expect(governedReceiptOperationIds).toContain(operation.catalogOperationId);
  expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
  expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
  expect(definition.authority.evidence.map((value: { kind: number }) => value.kind)).toEqual([
    3, 4,
  ]);
  expect(definition.transition.after).toBe('PRESENT_ADMITTED_REVISION_1');
  expect(definition.state.owner).toBe('control.store_retirement_admission');
  expect(Object.keys(definition.state.projection)).toHaveLength(12);
  const binding = bindStoreRetirementAdmission(context, uuid(6), undefined, state);
  const before = decodeCbor(binding.before.preimage) as unknown[];
  const after = decodeCbor(binding.after.preimage) as unknown[];
  expect(before[8]).toEqual(new Map());
  const fields = after[8] as Map<number, unknown>;
  expect(fields.size).toBe(12);
  expect(fields.get(8)).toEqual(Buffer.alloc(0));
  expect(fields.get(9)).toBe(9007199254740993n);
  expect(fields.get(10)).toBe(1800000000000000000n);
  expect(BigInt(fields.get(11) as number | bigint)).toBe(1800000060000n);
  expect(binding.after.reference.stateDigest).toEqual(
    createHash('sha256').update(binding.after.preimage).digest(),
  );
});

it('rejects a local-success profile, altered approval/operation/attempt, duplicate admission or absent after-state', () => {
  for (const [ctx, operationId, before, after] of [
    [{ ...context, catalogOperationId: 'CFG-OP-DELETE-LOCAL-EVIDENCE' }, uuid(6), undefined, state],
    [context, uuid(7), undefined, state],
    [context, uuid(6), state, state],
    [context, uuid(6), undefined, undefined],
    [context, uuid(6), undefined, { ...state, attemptId: uuid(8) }],
    [context, uuid(6), undefined, { ...state, approvalRequestId: uuid(8) }],
    [context, uuid(6), undefined, { ...state, lifecycleRevision: '9223372036854775808' }],
  ] as const)
    expect(() =>
      bindStoreRetirementAdmission(ctx as MutationContext, operationId, before, after),
    ).toThrow();
  const original = bindStoreRetirementAdmission(context, uuid(6), undefined, state).after.reference
    .stateDigest;
  for (const patch of [
    { hostDigest: '05'.repeat(32) },
    { attemptDigest: '05'.repeat(32) },
    { selectionDigest: '05'.repeat(32) },
    { sourceBindingDigest: `sha256:${'05'.repeat(32)}` },
    { retirementId: uuid(9) },
    { previousAttemptId: uuid(9) },
    { dispatchNotAfterMs: '1800000059999' },
  ])
    expect(
      bindStoreRetirementAdmission(context, uuid(6), undefined, { ...state, ...patch }).after
        .reference.stateDigest,
    ).not.toEqual(original);
});
