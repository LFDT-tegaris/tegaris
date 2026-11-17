import { expect, it } from 'vitest';
import {
  parseCandidateRetirementPreflight,
  parseFactRetirementPreflight,
} from './store-retirement-preflight.js';
import { retirementWireFixture } from './store-retirement-wire-fixture.js';
import {
  retirementAttempt,
  retirementAttemptDigest,
  retirementSelectionDigest,
  retirementWireDigest,
  retirementWireBytes,
} from './store-retirement-wire.js';

it('binds the bounded native advisory to its exact attempt and full-u64 selection without granting authority', () => {
  const { attempt } = retirementWireFixture();
  const base = {
    identity: 'OPENPC-FACT-RETIREMENT-PREFLIGHT-1',
    authority: 'ADVISORY_ONLY',
    attemptDigest: retirementAttemptDigest(attempt),
    selectionDigest: attempt.selection_digest,
  };
  const result = { state: 'CLEAR', checkedAtMs: '1800000000000', selection: attempt.selection };
  expect(parseFactRetirementPreflight(retirementWireBytes({ ...base, result }), attempt)).toEqual(
    result,
  );
  for (const bytes of [
    retirementWireBytes({ ...base, authority: 'ALLOW', result }),
    retirementWireBytes({ ...base, attemptDigest: 'b'.repeat(64), result }),
    retirementWireBytes({ ...base, selectionDigest: 'b'.repeat(64), result }),
    retirementWireBytes({ ...base, result: { ...result, checkedAtMs: '9223372036854775808' } }),
    retirementWireBytes({ ...base, result: { ...result, eligible: 'true' } }),
    retirementWireBytes({ ...base, holdFree: 'true', result }),
    retirementWireBytes({
      ...base,
      result: { state: 'BLOCKED', blocker: 'SOURCE_CHANGED', selection: attempt.selection },
    }),
    retirementWireBytes({ ...base, result: { state: 'UNAVAILABLE', noEffect: 'true' } }),
    retirementWireBytes({ ...base, result: { state: 'CLEAR', checkedAtMs: '1800000000000' } }),
  ])
    expect(() => parseFactRetirementPreflight(bytes, attempt)).toThrow();
  const blocked = { state: 'BLOCKED', blocker: 'REFERENCES_PROTECTED' };
  const unavailable = { state: 'UNAVAILABLE' };
  expect(
    parseFactRetirementPreflight(retirementWireBytes({ ...base, result: blocked }), attempt),
  ).toEqual(blocked);
  expect(
    parseFactRetirementPreflight(retirementWireBytes({ ...base, result: unavailable }), attempt),
  ).toEqual(unavailable);
});

it('candidate advisory binds the installed host and exact native selection without borrowing Fact authority', () => {
  const f = retirementWireFixture(),
    row = f.attempt.selection.rows[0]!;
  const selection = {
    class: 'CANDIDATE_PROJECTION' as const,
    source: f.attempt.selection.source,
    rows: [
      {
        candidate_id: row.candidate_id,
        candidate_feed_sequence: row.candidate_feed_sequence,
        payload_digest: row.payload_digest,
        payload_bytes: row.payload_bytes,
        checkpoint_digest: row.checkpoint_digest,
      },
    ],
  };
  const attempt = retirementAttempt.parse({
    ...f.attempt,
    store: 'openpc_candidate_index',
    selection,
    selection_digest: retirementSelectionDigest(f.attempt.scope, selection),
  });
  const host = { ...f.host, store: 'openpc_candidate_index' as const, target_id: 'candidates' };
  const base = {
    identity: 'OPENPC-CANDIDATE-RETIREMENT-PREFLIGHT-1',
    authority: 'ADVISORY_ONLY',
    hostDigest: retirementWireDigest(host),
    attemptDigest: retirementAttemptDigest(attempt),
    selectionDigest: attempt.selection_digest,
    result: { state: 'CLEAR', checkedAtMs: '1800000000000', selection },
  };
  expect(parseCandidateRetirementPreflight(retirementWireBytes(base), attempt, host)).toEqual(
    base.result,
  );
  for (const change of [
    { identity: 'OPENPC-FACT-RETIREMENT-PREFLIGHT-1' },
    { authority: 'EXECUTE' },
    { hostDigest: 'b'.repeat(64) },
    { attemptDigest: 'b'.repeat(64) },
    { selectionDigest: 'b'.repeat(64) },
    { result: { ...base.result, checkedAtMs: '9223372036854775808' } },
    {
      result: {
        ...base.result,
        selection: { ...selection, rows: [{ ...selection.rows[0], payload_bytes: 41n }] },
      },
    },
  ])
    expect(() =>
      parseCandidateRetirementPreflight(retirementWireBytes({ ...base, ...change }), attempt, host),
    ).toThrow();
  expect(() =>
    parseCandidateRetirementPreflight(retirementWireBytes(base), attempt, f.host),
  ).toThrow();
  expect(() =>
    parseCandidateRetirementPreflight(retirementWireBytes(base), attempt, {
      ...host,
      scope: { ...host.scope, privacy_domain_id: 'foreign' },
    }),
  ).toThrow();
  expect(() => parseFactRetirementPreflight(retirementWireBytes(base), attempt)).toThrow();
  const blocked = { state: 'BLOCKED', blocker: 'PUBLICATION_PROTECTED' };
  expect(
    parseCandidateRetirementPreflight(
      retirementWireBytes({ ...base, result: blocked }),
      attempt,
      host,
    ),
  ).toEqual(blocked);
});
