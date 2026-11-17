import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../../../../../../packages/security-kernel/src/business-transition/cbor.js';

import {
  assertWorkItemBusinessTransition,
  bindWorkItemBusinessState,
  type WorkItemBusinessState,
  type WorkItemStateCommand,
} from './work-item.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(2, '0').repeat(32)}`;
const scope = { participantId: id(2), privacyDomainId: id(3), aggregateId: id(5) };
const binding = { ...scope, aggregateType: 'work-item', profileDigest: Buffer.alloc(32, 1) };
const state: WorkItemBusinessState = {
  workItemId: scope.aggregateId,
  participantId: scope.participantId,
  privacyDomainId: scope.privacyDomainId,
  kind: 'DELIVERY_FAILURE',
  state: 'OPEN',
  assigneePrincipalId: null,
  resourceRef: `urn:openpc:resource:${id(6)}`,
  payloadDigest: digest(4),
  reasonDigest: digest(5),
  createdByPrincipalId: id(7),
  claimedByPrincipalId: null,
  completedByPrincipalId: null,
  revision: '1',
};
const create: WorkItemStateCommand = {
  kind: 'CREATE',
  actorPrincipalId: id(7),
  expectedRevision: '0',
  workItemKind: state.kind,
  assigneePrincipalId: null,
  resourceRef: state.resourceRef,
  payloadDigest: state.payloadDigest,
  reasonDigest: state.reasonDigest,
};
const update: WorkItemStateCommand = {
  kind: 'UPDATE',
  actorPrincipalId: id(8),
  expectedRevision: '1',
  replacementDigest: digest(9),
  reasonDigest: digest(10),
};
const claim: WorkItemStateCommand = {
  kind: 'CLAIM',
  actorPrincipalId: id(8),
  expectedRevision: '1',
};
const claimed: WorkItemBusinessState = {
  ...state,
  state: 'CLAIMED',
  assigneePrincipalId: id(8),
  claimedByPrincipalId: id(8),
  revision: '2',
};
const complete: WorkItemStateCommand = {
  kind: 'COMPLETE',
  actorPrincipalId: id(8),
  expectedRevision: '2',
};
const completed: WorkItemBusinessState = {
  ...claimed,
  state: 'COMPLETED',
  completedByPrincipalId: id(8),
  revision: '3',
};
const assert = (
  command: WorkItemStateCommand,
  before: WorkItemBusinessState | undefined,
  after: WorkItemBusinessState | undefined,
) => assertWorkItemBusinessTransition(scope, command, before, after);

describe('work-item durable business state', () => {
  it('binds absence and exact uint64 state using independent CBOR/hashlib vectors', () => {
    // Independent Python field-by-field CBOR oracle; this digest is an unadmitted fixture profile.
    const absent = bindWorkItemBusinessState(binding, undefined);
    expect(absent.reference).toMatchObject({ existence: 0, revision: 0n });
    expect(absent.reference.stateDigest.toString('hex')).toBe(
      'b99990d59c6fed5431729b8abd292e04b61cf0a1472ceb5af18eb06826f92d21',
    );
    const present = bindWorkItemBusinessState(binding, { ...state, revision: '9007199254740993' });
    expect(present.reference.revision).toBe(9007199254740993n);
    expect(present.reference.stateDigest.toString('hex')).toBe(
      '863f601199ae77d3f1e7a46693899125c821194f2c8136f7211e03094bb69695',
    );
  });

  it('encodes optional actor presence without null, synthetic UUIDs or public DTO omissions', () => {
    const projection = (row: WorkItemBusinessState) =>
      (decodeCbor(bindWorkItemBusinessState(binding, row).preimage) as unknown[])[8] as Map<
        number,
        unknown
      >;
    const open = projection(state);
    for (const key of [6, 8, 10]) {
      expect(open.get(key)).toBe(0n);
      expect(open.has(key + 1)).toBe(false);
    }
    const final = projection(completed);
    for (const key of [6, 8, 10]) {
      expect(final.get(key)).toBe(1n);
      expect(final.get(key + 1)).toEqual(Buffer.from(id(8).replaceAll('-', ''), 'hex'));
    }
    expect(final.get(3)).toEqual(Buffer.alloc(32, 4));
    expect(final.get(4)).toEqual(Buffer.alloc(32, 5));
    expect(final.get(5)).toEqual(Buffer.from(id(7).replaceAll('-', ''), 'hex'));
  });

  it('rejects cross-participant, cross-privacy and substituted aggregate rows on either side', () => {
    for (const change of [
      { participantId: id(20) },
      { privacyDomainId: id(20) },
      { workItemId: id(20) },
    ]) {
      expect(() => bindWorkItemBusinessState(binding, { ...state, ...change })).toThrow();
      expect(() => assert(create, undefined, { ...state, ...change })).toThrow();
      expect(() => assert(claim, { ...state, ...change }, claimed)).toThrow();
      expect(() => assert(claim, state, { ...claimed, ...change })).toThrow();
    }
    expect(() =>
      bindWorkItemBusinessState({ ...binding, aggregateType: 'work-items' }, state),
    ).toThrow();
    expect(() =>
      bindWorkItemBusinessState({ ...binding, participantId: 'invalid' }, undefined),
    ).toThrow();
    expect(() =>
      bindWorkItemBusinessState({ ...binding, profileDigest: Buffer.alloc(31) }, state),
    ).toThrow();
    expect(
      bindWorkItemBusinessState({ ...binding, profileDigest: Buffer.alloc(32, 2) }, state).reference
        .stateDigest,
    ).not.toEqual(bindWorkItemBusinessState(binding, state).reference.stateDigest);
  });

  it('rejects malformed, unknown and inconsistent persisted fields', () => {
    for (const change of [
      { extra: true },
      { revision: '01' },
      { revision: '0' },
      { revision: '18446744073709551616' },
      { payloadDigest: `sha256:${'AA'.repeat(32)}` },
      { reasonDigest: digest(5).slice(0, -1) },
      { resourceRef: 'https://unregistered.example' },
      { kind: 'UNKNOWN' },
      { state: 'READY' },
      { createdByPrincipalId: 'invalid' },
      { assigneePrincipalId: '' },
      { claimedByPrincipalId: id(8) },
      { completedByPrincipalId: id(8) },
    ])
      expect(() =>
        bindWorkItemBusinessState(binding, { ...state, ...change } as WorkItemBusinessState),
      ).toThrow();
    expect(() =>
      bindWorkItemBusinessState(binding, { ...claimed, assigneePrincipalId: id(9) }),
    ).toThrow();
    expect(() =>
      bindWorkItemBusinessState(binding, { ...completed, completedByPrincipalId: id(9) }),
    ).toThrow();
  });

  it('allows only exact absent-to-open creation, including a preassigned work item', () => {
    expect(() => assert(create, undefined, state)).not.toThrow();
    expect(() =>
      assert({ ...create, assigneePrincipalId: id(8) }, undefined, {
        ...state,
        assigneePrincipalId: id(8),
      }),
    ).not.toThrow();
    expect(() => assert(create, state, state)).toThrow();
    expect(() => assert(create, undefined, undefined)).toThrow();
    for (const change of [
      { state: 'CANCELLED' },
      { revision: '2' },
      { kind: 'REMEDIATION' },
      { assigneePrincipalId: id(8) },
      { resourceRef: `urn:openpc:resource:${id(9)}` },
      { payloadDigest: digest(9) },
      { reasonDigest: digest(9) },
      { createdByPrincipalId: id(8) },
    ])
      expect(() =>
        assert(create, undefined, { ...state, ...change } as WorkItemBusinessState),
      ).toThrow();
  });

  it('requires an open item, changed candidate digest and exact one-revision update', () => {
    const next = { ...state, payloadDigest: digest(9), reasonDigest: digest(10), revision: '2' };
    expect(() => assert(update, state, next)).not.toThrow();
    for (const change of [
      { payloadDigest: state.payloadDigest },
      { reasonDigest: state.reasonDigest },
      { revision: '1' },
      { revision: '3' },
      { state: 'CANCELLED' },
      { assigneePrincipalId: id(8) },
      { kind: 'APPROVAL' },
      { resourceRef: `urn:openpc:resource:${id(9)}` },
      { createdByPrincipalId: id(8) },
    ])
      expect(() =>
        assert(update, state, { ...next, ...change } as WorkItemBusinessState),
      ).toThrow();
    expect(() =>
      assert({ ...update, replacementDigest: state.payloadDigest }, state, {
        ...next,
        payloadDigest: state.payloadDigest,
      }),
    ).toThrow();
    expect(() => assert({ ...update, expectedRevision: '2' }, state, next)).toThrow();
    expect(() => assert(update, undefined, next)).toThrow();
    expect(() => assert(update, state, undefined)).toThrow();
    expect(() =>
      assert({ ...update, expectedRevision: '2' }, claimed, {
        ...claimed,
        payloadDigest: digest(9),
        reasonDigest: digest(10),
        revision: '3',
      }),
    ).toThrow();
  });

  it('permits only the assignee to claim and rejects the second claimant against durable state', () => {
    expect(() => assert(claim, state, claimed)).not.toThrow();
    expect(() => assert(claim, { ...state, assigneePrincipalId: id(8) }, claimed)).not.toThrow();
    expect(() => assert(claim, { ...state, assigneePrincipalId: id(9) }, claimed)).toThrow();
    expect(() => assert({ ...claim, actorPrincipalId: id(9) }, state, claimed)).toThrow();
    expect(() => assert(claim, claimed, { ...claimed, revision: '3' })).toThrow();
    expect(() =>
      assert({ ...claim, expectedRevision: '2' }, claimed, { ...claimed, revision: '3' }),
    ).toThrow();
    for (const change of [
      { revision: '3' },
      { payloadDigest: digest(9) },
      { reasonDigest: digest(9) },
      { kind: 'REMEDIATION' },
      { resourceRef: `urn:openpc:resource:${id(9)}` },
      { createdByPrincipalId: id(8) },
      { completedByPrincipalId: id(8) },
      { assigneePrincipalId: id(9), claimedByPrincipalId: id(9) },
    ])
      expect(() =>
        assert(claim, state, { ...claimed, ...change } as WorkItemBusinessState),
      ).toThrow();
  });

  it('requires the original claimant to complete without changing the task or its assignment', () => {
    expect(() => assert(complete, claimed, completed)).not.toThrow();
    expect(() => assert({ ...complete, actorPrincipalId: id(9) }, claimed, completed)).toThrow();
    expect(() => assert({ ...complete, expectedRevision: '1' }, state, completed)).toThrow();
    expect(() =>
      assert({ ...complete, expectedRevision: '3' }, completed, { ...completed, revision: '4' }),
    ).toThrow();
    for (const change of [
      { revision: '4' },
      { payloadDigest: digest(9) },
      { reasonDigest: digest(9) },
      { kind: 'REMEDIATION' },
      { resourceRef: `urn:openpc:resource:${id(9)}` },
      { createdByPrincipalId: id(8) },
      { assigneePrincipalId: id(9), claimedByPrincipalId: id(9), completedByPrincipalId: id(9) },
    ])
      expect(() =>
        assert(complete, claimed, { ...completed, ...change } as WorkItemBusinessState),
      ).toThrow();
  });

  it('retains cancelled history without allowing update, claim, completion or resurrection', () => {
    const cancelled = { ...claimed, state: 'CANCELLED' as const };
    expect(() => bindWorkItemBusinessState(binding, cancelled)).not.toThrow();
    for (const command of [update, claim, complete])
      expect(() => assert({ ...command, expectedRevision: '2' }, cancelled, completed)).toThrow();
    expect(() => assert(create, cancelled, state)).toThrow();
  });

  it('rejects malformed command actors, stale/noncanonical revisions and unknown commands', () => {
    for (const change of [
      { actorPrincipalId: 'invalid' },
      { expectedRevision: '01' },
      { expectedRevision: '0' },
      { expectedRevision: '18446744073709551616' },
      { kind: 'CANCEL' },
      { extra: true },
    ])
      expect(() =>
        assert({ ...claim, ...change } as WorkItemStateCommand, state, claimed),
      ).toThrow();
    const high = { ...state, revision: '9007199254740993' };
    expect(() =>
      assert({ ...claim, expectedRevision: high.revision }, high, {
        ...claimed,
        revision: '9007199254740994',
      }),
    ).not.toThrow();
    const exhausted = { ...state, revision: '18446744073709551615' };
    expect(() =>
      assert({ ...claim, expectedRevision: exhausted.revision }, exhausted, {
        ...claimed,
        revision: '18446744073709551616',
      }),
    ).toThrow();
  });
});
