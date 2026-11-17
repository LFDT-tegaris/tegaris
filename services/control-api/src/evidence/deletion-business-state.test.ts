import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  businessTransitionProfileForOperation,
  signingRoleProfiles,
} from '@openpc/security-kernel';
import { decodeCbor } from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import type { MutationContext } from '../configuration/persistence/types.js';
import { bindDeletionTransition } from './deletion-business-state.js';

const uuid = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const digest = `sha256:${'01'.repeat(32)}`;
const baseContext = {
  catalogOperationId: 'CFG-OP-DELETE-PROJECTION-BATCH',
  resourceId: uuid(1),
  authorization: { participantId: uuid(2), privacyDomainId: uuid(3), approvalRequestId: uuid(4) },
} as MutationContext;
const state = {
  retentionPolicyId: uuid(5),
  targetSelectorDigest: digest,
  eligibilityDigest: digest,
  beforeDigest: digest,
  afterDigest: digest,
  attemptId: uuid(6),
  operationId: uuid(7),
  approvalRequestId: uuid(4),
  revision: '1' as const,
  state: 'SUCCEEDED' as const,
  deletedCount: '1' as const,
  deletedBytes: '16',
  retainedAliasCount: '0' as const,
  beforeUsedBytes: '9007199254741010',
  afterUsedBytes: '9007199254740994',
  startedAtNs: '1800000000000000000',
  completedAtNs: '1800000000000001000',
};

it.each([
  ['CFG-OP-DELETE-PROJECTION-BATCH', 1],
  ['CFG-OP-DELETE-PROJECTION-BATCH', 2],
  ['CFG-OP-DELETE-PROJECTION-BATCH', 3],
  ['CFG-OP-DELETE-LOCAL-EVIDENCE', 2],
  ['CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH', 2],
] as const)(
  'binds %s v%s, governed authority and lossless counters together',
  (catalogOperationId, version) => {
    const context = { ...baseContext, catalogOperationId };
    const profile = businessTransitionProfileForOperation(context.catalogOperationId, version)!;
    const definition = JSON.parse(profile.definitionCanonicalJson);
    expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
    expect(definition.authority.evidence.map((entry: { kind: number }) => entry.kind)).toEqual([
      3, 4,
    ]);
    expect(definition.state.owner).toBe('control.deletion_job');
    const binding = bindDeletionTransition(context, uuid(7), undefined, state, version);
    for (const side of [binding.before, binding.after]) {
      expect((decodeCbor(side.preimage) as unknown[])[1]).toEqual(
        Buffer.from(profile.profileDigest.slice(7), 'hex'),
      );
      expect(side.reference.stateDigest).toEqual(
        createHash('sha256').update(side.preimage).digest(),
      );
    }
    expect((decodeCbor(binding.before.preimage) as unknown[])[8]).toEqual(new Map());
    const fields = (decodeCbor(binding.after.preimage) as unknown[])[8] as Map<number, unknown>;
    expect(fields.size).toBe(Object.keys(definition.state.projection).length);
    expect(fields.get(13)).toBe(9007199254741010n);
    expect(fields.get(14)).toBe(9007199254740994n);
  },
);

it('separates producer profile bindings and rejects unadmitted versions or an inconsistent physical effect', () => {
  const context = baseContext;
  const first = bindDeletionTransition(context, uuid(7), undefined, state, 1);
  const second = bindDeletionTransition(context, uuid(7), undefined, state, 2);
  expect(first.before.reference.stateDigest).not.toEqual(second.before.reference.stateDigest);
  expect(first.after.reference.stateDigest).not.toEqual(second.after.reference.stateDigest);
  const third = bindDeletionTransition(context, uuid(7), undefined, state, 3);
  expect(third.before.reference.stateDigest).not.toEqual(second.before.reference.stateDigest);
  expect(third.after.reference.stateDigest).not.toEqual(second.after.reference.stateDigest);
  expect(() => bindDeletionTransition(context, uuid(7), undefined, state, 4)).toThrow();
  for (const patch of [
    { operationId: uuid(8) },
    { approvalRequestId: uuid(8) },
    { afterUsedBytes: state.beforeUsedBytes },
    { completedAtNs: '1' },
  ])
    expect(() =>
      bindDeletionTransition(context, uuid(7), undefined, { ...state, ...patch }, 2),
    ).toThrow();
});

it('admits the exact physical runtime profile and keeps its byte limit separate from other classes', async () => {
  const { readFile } = await import('node:fs/promises');
  const { definitionDigest } =
    await import('../../../../packages/security-kernel/src/business-transition/definition.js');
  const definition = JSON.parse(
    await readFile(
      new URL(
        '../../../../schemas/canonical/business-transition-profiles/evidence-deletion-runtime-artifact-v1.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
  expect(definition.definitionDigest).toBe(
    `sha256:${definitionDigest(definition).toString('hex')}`,
  );
  expect(definition.profileId).toBe('pc.control.evidence-deletion.runtime-artifact');
  expect(definition.authority.evidence.map((entry: { kind: number }) => entry.kind)).toEqual([
    3, 4,
  ]);
  expect(definition.events.map((entry: { cardinality: number }) => entry.cardinality)).toEqual([1]);
  expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(definition.profileId);
  expect(
    businessTransitionProfileForOperation(definition.catalogOperationId, 1)?.profileDigest,
  ).toBe(definition.definitionDigest);
  const context = { ...baseContext, catalogOperationId: definition.catalogOperationId };
  const physical = {
    ...state,
    deletedBytes: '4194304',
    beforeUsedBytes: '4194304',
    afterUsedBytes: '0',
  };
  const bound = bindDeletionTransition(context, uuid(7), undefined, physical);
  expect(((decodeCbor(bound.after.preimage) as unknown[])[8] as Map<number, unknown>).get(9)).toBe(
    4194304n,
  );
  expect(() => bindDeletionTransition(context, uuid(7), undefined, physical, 2)).toThrow();
  expect(() =>
    bindDeletionTransition(context, uuid(7), undefined, {
      ...physical,
      deletedBytes: '4194305',
      beforeUsedBytes: '4194305',
    }),
  ).toThrow();
  // The class-specific limit does not widen existing evidence classes.
  expect(() =>
    bindDeletionTransition(baseContext, uuid(7), undefined, {
      ...state,
      deletedBytes: '4194304',
      beforeUsedBytes: '4194304',
      afterUsedBytes: '0',
    }),
  ).toThrow();
});
