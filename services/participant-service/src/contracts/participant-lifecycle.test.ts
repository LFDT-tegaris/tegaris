import { describe, expect, it } from 'vitest';
import {
  participantLifecycleChange,
  participantLifecycleOperations,
} from './participant-lifecycle.js';
const source = '018f0000-0000-7000-8000-000000000101',
  successor = '018f0000-0000-7000-8000-000000000102';
const base = {
  participantId: source,
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  expectedRevision: '1',
  expectedEpoch: '1',
  reason: 'Retain history and reduce authority.',
  idempotencyKey: 'lifecycle-regression-0001',
};
describe('governed Participant lifecycle boundary', () => {
  it('rejects rounded, overflowed and ambiguous epoch representations', () => {
    for (const expectedEpoch of [1, '0', '01', '18446744073709551616', '1e1'])
      expect(
        participantLifecycleChange.safeParse({ ...base, mutation: 'ARCHIVE', expectedEpoch })
          .success,
      ).toBe(false);
  });
  it('requires a closed nonempty reduction and rejects replacement or widening fields', () => {
    for (const envelopeIds of [[], [source, source]])
      expect(
        participantLifecycleChange.safeParse({ ...base, mutation: 'SHRINK', envelopeIds }).success,
      ).toBe(false);
    expect(
      participantLifecycleChange.safeParse({
        ...base,
        mutation: 'SHRINK',
        envelopeIds: [source],
        actionIntentIds: ['arbitrary-grant'],
      }).success,
    ).toBe(false);
    expect(
      participantLifecycleChange.parse({ ...base, mutation: 'SHRINK', envelopeIds: [source] })
        .mutation,
    ).toBe('SHRINK');
  });
  it('cannot hide new grants in restore or transfer to the same owner', () => {
    expect(
      participantLifecycleChange.safeParse({ ...base, mutation: 'RESTORE', grants: [source] })
        .success,
    ).toBe(false);
    const transfer = {
      ...base,
      mutation: 'TRANSFER',
      logicalContractId: source,
      successorLogicalContractId: successor,
      successorParticipantId: source,
      successorPrivacyDomainId: base.privacyDomainId,
      expectedSuccessorEpoch: '1',
      contentDigest: `sha256:${'aa'.repeat(32)}`,
    };
    expect(participantLifecycleChange.safeParse(transfer).success).toBe(false);
    expect(
      participantLifecycleChange.parse({ ...transfer, successorParticipantId: successor }).mutation,
    ).toBe('TRANSFER');
  });
  it('keeps terminal authority states out of every governed transition', () => {
    for (const operation of participantLifecycleOperations) {
      expect(operation.makerCheckerRequired && operation.webauthnStepUpRequired).toBe(true);
      expect(
        operation.allowedFromStates.every((state) => ['ACTIVE', 'SUSPENDED'].includes(state)),
      ).toBe(true);
    }
  });
});
