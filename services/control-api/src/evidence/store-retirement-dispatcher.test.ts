import { expect, it } from 'vitest';
import {
  parseFactRetirementTarget,
  parseStoreRetirementTarget,
} from './store-retirement-dispatcher.js';
import { retirementWireFixture } from './store-retirement-wire-fixture.js';
import { retirementWireBytes, retirementWireDigest } from './store-retirement-wire.js';

it('keeps absent target readback UNKNOWN and rejects foreign, affirmative and ambiguous target envelopes', () => {
  const { host } = retirementWireFixture();
  const base = {
    identity: 'OPENPC-FACT-RETIREMENT-TARGET-1',
    hostDigest: retirementWireDigest(host),
  };
  const unknown = retirementWireBytes({ ...base, result: { state: 'UNKNOWN' } });
  expect(parseFactRetirementTarget(unknown, host, true)).toBeUndefined();
  expect(() => parseFactRetirementTarget(unknown, host, false)).toThrow();
  for (const bytes of [
    retirementWireBytes({ ...base, hostDigest: 'a'.repeat(64), result: { state: 'UNKNOWN' } }),
    retirementWireBytes({ ...base, result: { state: 'NOT_FOUND' } }),
    retirementWireBytes({ ...base, result: { state: 'UNKNOWN', noEffect: 'true' } }),
    retirementWireBytes({ ...base, result: { state: 'TERMINAL', signedWireHex: '0' } }),
    retirementWireBytes({ ...base, result: { state: 'APPLIED' } }),
  ])
    expect(() => parseFactRetirementTarget(bytes, host, true)).toThrow();
  // Extracting terminal bytes is not signature verification or an effect claim.
  expect(
    parseFactRetirementTarget(
      retirementWireBytes({ ...base, result: { state: 'TERMINAL', signedWireHex: '00ff' } }),
      host,
      false,
    ),
  ).toEqual(Buffer.from([0, 255]));
});

it('binds candidate readback to its separately installed host and target protocol', () => {
  const host = { ...retirementWireFixture().host, store: 'openpc_candidate_index' as const };
  const envelope = {
    identity: 'OPENPC-CANDIDATE-RETIREMENT-TARGET-1',
    hostDigest: retirementWireDigest(host),
    result: { state: 'UNKNOWN' },
  };
  expect(parseStoreRetirementTarget(retirementWireBytes(envelope), host, true)).toBeUndefined();
  expect(() => parseStoreRetirementTarget(retirementWireBytes(envelope), host, false)).toThrow();
  expect(() => parseFactRetirementTarget(retirementWireBytes(envelope), host, true)).toThrow();
  expect(() =>
    parseStoreRetirementTarget(
      retirementWireBytes({ ...envelope, identity: 'OPENPC-FACT-RETIREMENT-TARGET-1' }),
      host,
      true,
    ),
  ).toThrow();
  expect(() =>
    parseStoreRetirementTarget(retirementWireBytes(envelope), retirementWireFixture().host, true),
  ).toThrow();
  expect(
    parseStoreRetirementTarget(
      retirementWireBytes({ ...envelope, result: { state: 'TERMINAL', signedWireHex: '00ff' } }),
      host,
      false,
    ),
  ).toEqual(Buffer.from([0, 255]));
});
