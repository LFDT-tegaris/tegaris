import { expect, it } from 'vitest';
import {
  parseFactRetirementSelection,
  factRetirementSelectionRequest,
} from './store-retirement-selection.js';
import { factRetirementPlanInput } from './store-retirement-contracts.js';
import { retirementWireFixture } from './store-retirement-wire-fixture.js';
import { retirementWireBytes } from './store-retirement-wire.js';

it('binds native selection to exact scope, candidate and signed custody without granting eligibility', () => {
  const id = '018f0000-0000-7000-8000-000000000101';
  const request = {
    participantId: id,
    privacyDomainId: id,
    candidateId: id,
    signedFactDigest: 'a'.repeat(64),
  };
  const { attempt } = retirementWireFixture();
  attempt.selection.rows[0]!.candidate_id = id;
  const response = {
    ...request,
    identity: 'OPENPC-FACT-RETIREMENT-SELECTION-1',
    authority: 'ADVISORY_ONLY',
    result: { state: 'SELECTED', selection: attempt.selection },
  };
  expect(parseFactRetirementSelection(retirementWireBytes(response), request)).toEqual(
    attempt.selection,
  );
  const patches: Array<Record<string, Parameters<typeof retirementWireBytes>[0]>> = [
    { participantId: '018f0000-0000-7000-8000-000000000102' },
    { privacyDomainId: '018f0000-0000-7000-8000-000000000102' },
    { candidateId: '018f0000-0000-7000-8000-000000000102' },
    { signedFactDigest: 'b'.repeat(64) },
    { identity: 'OTHER' },
    { authority: 'EXECUTE' },
    { eligible: 'CLAIMED' },
    { result: { state: 'UNAVAILABLE' } },
    {
      result: {
        state: 'SELECTED',
        selection: {
          ...attempt.selection,
          rows: [{ ...attempt.selection.rows[0]!, candidate_id: 'other' }],
        },
      },
    },
    {
      result: {
        state: 'SELECTED',
        selection: {
          ...attempt.selection,
          rows: [{ ...attempt.selection.rows[0]!, signed_fact_digest: 'b'.repeat(64) }],
        },
      },
    },
  ];
  for (const patch of patches)
    expect(() =>
      parseFactRetirementSelection(retirementWireBytes({ ...response, ...patch }), request),
    ).toThrow();
  for (const patch of [
    { eligible: true },
    { database: 'other' },
    { signedFactDigest: 'sha256:' + 'a'.repeat(64) },
  ])
    expect(factRetirementSelectionRequest.safeParse({ ...request, ...patch }).success).toBe(false);
  const plan = { hostDigest: 'a'.repeat(64), retentionPolicyId: `urn:openpc:resource:${id}` };
  expect(factRetirementPlanInput.parse(plan)).toEqual(plan);
  for (const patch of [
    { selectionWireHex: '00' },
    { recordRefs: [] },
    { eligible: true },
    { nativeSourceCheck: 'CLEAR' },
  ])
    expect(factRetirementPlanInput.safeParse({ ...plan, ...patch }).success).toBe(false);
});
