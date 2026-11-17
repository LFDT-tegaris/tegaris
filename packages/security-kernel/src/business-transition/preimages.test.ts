import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import {
  commandCommittedDigest,
  decodeCommandCommitted,
  encodeCommandCommitted,
} from './command-event.js';
import { transitionStatePreimage, transitionStateRef } from './state.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const command = {
  commandId: id(4),
  aggregateRef: `urn:openpc:resource:${id(5)}`,
  actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
  intentDigest: `sha256:${'04'.repeat(32)}`,
};
const stateContext = {
  profileDigest: Buffer.alloc(32, 1),
  participantId: id(2),
  privacyDomainId: id(3),
  aggregateType: 'session',
  aggregateId: id(5),
};
const projection = new Map<number, CborValue>([
  [0, 'ACTIVE'],
  [1, 9_007_199_254_740_993n],
]);

// Independently encoded from the adopted field order and checked with Python
// hashlib; these constants never call a product codec to derive expected bytes.
const commandHex =
  'a40050018f000000007000800000000000000401783875726e3a6f70656e70633a7265736f757263653a30313866303030302d303030302d373030302d383030302d30303030303030303030303502781e4143542d4944454e544954595f44454c4554455f53455353494f4e2d56310358200404040404040404040404040404040404040404040404040404040404040404';
const stateHex =
  '89781e70632e636f6e74726f6c2e7472616e736974696f6e2d73746174652e76315820010101010101010101010101010101010101010101010101010101010101010150018f000000007000800000000000000250018f00000000700080000000000000036773657373696f6e50018f0000000070008000000000000005011b0020000000000001a20066414354495645011b0020000000000001';

describe('acyclic command event projection', () => {
  it('uses exact registered four-field CBOR bytes and exposes the existing JSON projection', () => {
    expect(encodeCommandCommitted(command).toString('hex')).toBe(commandHex);
    expect(decodeCommandCommitted(Buffer.from(commandHex, 'hex'))).toEqual(command);
    expect(commandCommittedDigest(command).toString('hex')).toBe(
      '4cbb7759233f3fdaee68114c2008a9169585467c2eb4fc73ca5f76705eae774b',
    );
    expect(commandCommittedDigest(command)).not.toEqual(
      createHash('sha256').update(JSON.stringify(command)).digest(),
    );
  });

  it('rejects self-receipt links, extra fields and malformed event identities', () => {
    for (const altered of [
      { ...command, receiptDigest: `sha256:${'ab'.repeat(32)}` },
      { ...command, commandId: id(4).replace('-7000-', '-4000-') },
      { ...command, aggregateRef: 'urn:openpc:resource:invalid' },
      { ...command, actionIntentId: 'unregistered-action' },
      { ...command, intentDigest: `sha256:${'A'.repeat(64)}` },
    ])
      expect(() => encodeCommandCommitted(altered)).toThrow();
    for (const key of [0, 1, 2, 3]) {
      const map = decodeCbor(Buffer.from(commandHex, 'hex')) as Map<number, CborValue>;
      map.delete(key);
      expect(() => decodeCommandCommitted(encodeCbor(map))).toThrow();
      map.set(key, 0n);
      expect(() => decodeCommandCommitted(encodeCbor(map))).toThrow();
    }
    const extra = decodeCbor(Buffer.from(commandHex, 'hex')) as Map<number, CborValue>;
    extra.set(4, Buffer.alloc(32));
    expect(() => decodeCommandCommitted(encodeCbor(extra))).toThrow();
  });
});

describe('scoped transition state preimage', () => {
  it('matches independent bytes above the JavaScript integer precision boundary', () => {
    expect(
      transitionStatePreimage(stateContext, 1, 9_007_199_254_740_993n, projection).toString('hex'),
    ).toBe(stateHex);
    expect(
      transitionStateRef(stateContext, 1, 9_007_199_254_740_993n, projection).stateDigest.toString(
        'hex',
      ),
    ).toBe('75e1636b3d8129c48750323cf249e2fc432b598e7c560cba57b8feba83a9b8cd');
  });

  it('binds the profile, both scopes, aggregate identity, existence, revision and projection', () => {
    const baseline = transitionStateRef(stateContext, 1, 7n, projection).stateDigest;
    for (const altered of [
      { ...stateContext, profileDigest: Buffer.alloc(32, 2) },
      { ...stateContext, participantId: id(9) },
      { ...stateContext, privacyDomainId: id(9) },
      { ...stateContext, aggregateType: 'principal' },
      { ...stateContext, aggregateId: id(9) },
    ])
      expect(transitionStateRef(altered, 1, 7n, projection).stateDigest).not.toEqual(baseline);
    expect(transitionStateRef(stateContext, 2, 7n, projection).stateDigest).not.toEqual(baseline);
    expect(transitionStateRef(stateContext, 1, 8n, projection).stateDigest).not.toEqual(baseline);
    expect(transitionStateRef(stateContext, 1, 7n, new Map()).stateDigest).not.toEqual(baseline);
  });

  it('rejects malformed scope, digest and revision without claiming profile admission', () => {
    expect(() => transitionStateRef(stateContext, 0, 1n, new Map())).toThrow();
    expect(() => transitionStateRef(stateContext, 1, MAX_UINT64 + 1n, new Map())).toThrow();
    expect(() => transitionStateRef(stateContext, 1, -1n, new Map())).toThrow();
    expect(() =>
      transitionStateRef({ ...stateContext, privacyDomainId: 'invalid' }, 1, 1n, new Map()),
    ).toThrow();
    expect(() =>
      transitionStateRef({ ...stateContext, profileDigest: Buffer.alloc(31) }, 1, 1n, new Map()),
    ).toThrow();
  });
});
