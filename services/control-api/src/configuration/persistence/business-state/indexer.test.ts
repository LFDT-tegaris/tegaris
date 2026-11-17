import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../../../../../../packages/security-kernel/src/business-transition/cbor.js';

import {
  assertIndexerBusinessTransition,
  bindIndexerBusinessState,
  type IndexerBusinessState,
} from './indexer.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const context = {
  profileDigest: Buffer.alloc(32, 1),
  participantId: id(2),
  privacyDomainId: id(3),
  aggregateType: 'indexer-profile',
  aggregateId: id(5),
};
const state: IndexerBusinessState = {
  engine: 'CLIENT_INDEXER',
  engineVersion: '1.0.0',
  methodProfileDigest: `sha256:${'04'.repeat(32)}`,
  state: 'REGISTERED',
  policyGenerationDigest: `sha256:${'05'.repeat(32)}`,
  revision: '1',
};
const command = {
  kind: 'CREATE',
  engine: state.engine,
  engineVersion: state.engineVersion,
  methodProfileDigest: state.methodProfileDigest,
} as const;

// Independent field-by-field Python CBOR encoding and hashlib oracle; the test
// profile digest is deliberately unadmitted and establishes no receipt authority.
const absentHex =
  '89781e70632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76315820010101010101010101010101010101010101010101010101010101010101010150018f000000007000800000000000000250018f00000000700080000000000000036f696e64657865722d70726f66696c6550018f00000000700080000000000000050000a0';
const presentHex =
  '89781e70632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76315820010101010101010101010101010101010101010101010101010101010101010150018f000000007000800000000000000250018f00000000700080000000000000036f696e64657865722d70726f66696c6550018f0000000070008000000000000005011b0020000000000001a5006e434c49454e545f494e44455845520165312e302e300258200404040404040404040404040404040404040404040404040404040404040404036a524547495354455245440458200505050505050505050505050505050505050505050505050505050505050505';

describe('indexer durable business state', () => {
  it('uses the versioned presence projection and never reinterprets legacy receipts', () => {
    const initial = { ...state, policyGenerationDigest: null };
    expect(() => bindIndexerBusinessState(context, initial)).toThrow();
    const absent = decodeCbor(bindIndexerBusinessState(context, initial, 2).preimage) as unknown[];
    const absentProjection = absent[8] as Map<number, unknown>;
    expect(absentProjection.get(4)).toBe(0n);
    expect(absentProjection.has(5)).toBe(false);
    const present = decodeCbor(bindIndexerBusinessState(context, state, 2).preimage) as unknown[];
    const presentProjection = present[8] as Map<number, unknown>;
    expect(presentProjection.get(4)).toBe(1n);
    expect(presentProjection.get(5)).toEqual(Buffer.alloc(32, 5));
    expect(bindIndexerBusinessState(context, state, 2).reference.stateDigest).not.toEqual(
      bindIndexerBusinessState(context, state, 1).reference.stateDigest,
    );
    expect(() => bindIndexerBusinessState(context, state, 3)).toThrow();
    expect(() =>
      assertIndexerBusinessTransition(
        { kind: 'UPDATE', expectedRevision: '1', replacementDigest: state.methodProfileDigest },
        initial,
        { ...state, revision: '2' },
      ),
    ).not.toThrow();
  });
  it('binds canonical absence and actual state above the JS precision boundary', () => {
    const absent = bindIndexerBusinessState(context, undefined);
    expect(absent.preimage.toString('hex')).toBe(absentHex);
    expect(absent.reference.stateDigest.toString('hex')).toBe(
      '1106750e0465b24868c47a7692cef451bab5be920a024ead5ba5a02442c51b67',
    );
    const present = bindIndexerBusinessState(context, { ...state, revision: '9007199254740993' });
    expect(present.preimage.toString('hex')).toBe(presentHex);
    expect(present.reference.stateDigest.toString('hex')).toBe(
      '1b2cf6ae9ba88d88dd1cbe5b09e9b58d1f2d29dfce666f84699b0903ad3c5646',
    );
  });

  it('rejects unknown state fields, malformed digests, noncanonical versions and out-of-range revisions', () => {
    for (const altered of [
      { ...state, evidenceDigest: `sha256:${'06'.repeat(32)}` },
      { ...state, methodProfileDigest: `sha256:${'FF'.repeat(32)}` },
      { ...state, state: 'PENDING' },
      { ...state, engineVersion: 'e\u0301' },
      { ...state, revision: '01' },
      { ...state, revision: '18446744073709551616' },
    ])
      expect(() => bindIndexerBusinessState(context, altered as IndexerBusinessState)).toThrow();
    expect(() =>
      bindIndexerBusinessState({ ...context, aggregateType: 'indexer-profiles' }, state),
    ).toThrow();
  });

  it('requires creation to establish the requested registered resource exactly once', () => {
    expect(() => assertIndexerBusinessTransition(command, undefined, state)).not.toThrow();
    for (const after of [
      undefined,
      { ...state, state: 'ACTIVE' as const },
      { ...state, revision: '2' },
      { ...state, engineVersion: '2.0.0' },
      { ...state, methodProfileDigest: `sha256:${'06'.repeat(32)}` },
    ])
      expect(() => assertIndexerBusinessTransition(command, undefined, after)).toThrow();
    expect(() => assertIndexerBusinessTransition(command, state, state)).toThrow();
  });

  it('rejects revision-only, stale, missing and unrelated updates while accepting real policy rebinding', () => {
    const update = {
      kind: 'UPDATE',
      expectedRevision: '1',
      replacementDigest: state.methodProfileDigest,
    } as const;
    const next = { ...state, revision: '2' };
    expect(() => assertIndexerBusinessTransition(update, state, next)).toThrow();
    const rebound = { ...next, policyGenerationDigest: `sha256:${'06'.repeat(32)}` };
    expect(() => assertIndexerBusinessTransition(update, state, rebound)).not.toThrow();
    expect(() =>
      assertIndexerBusinessTransition({ ...update, expectedRevision: '0' }, state, rebound),
    ).toThrow();
    expect(() => assertIndexerBusinessTransition(update, undefined, rebound)).toThrow();
    expect(() => assertIndexerBusinessTransition(update, state, undefined)).toThrow();
    for (const after of [
      { ...rebound, state: 'ACTIVE' as const },
      { ...rebound, engineVersion: '2.0.0' },
      { ...rebound, revision: '3' },
    ])
      expect(() => assertIndexerBusinessTransition(update, state, after)).toThrow();
  });
});
