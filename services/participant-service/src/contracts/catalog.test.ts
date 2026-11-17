import { describe, expect, it } from 'vitest';

import {
  participantContractTypes,
  participantEvents,
  participantOperations,
  participantStates,
} from './catalog.js';

describe('participant contract catalog', () => {
  it('owns the frozen participant-side denominator', () => {
    expect(participantContractTypes).toHaveLength(5);
    const extensionOperations = [
      'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE',
      'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE',
      'ID-OP-ENVELOPE-REVOKE',
    ];
    expect(
      participantOperations
        .filter((operation) => !extensionOperations.includes(operation.id))
        .map((operation) => operation.id),
    ).toEqual([
      'ID-OP-PARTICIPANT-CREATE',
      'ID-OP-PARTICIPANT-ACTIVATE',
      'ID-OP-ENVELOPE-CREATE',
      'ID-OP-ENVELOPE-ACTIVATE',
      'ID-OP-ASSIGNMENT-CREATE',
      'ID-OP-ASSIGNMENT-REVOKE',
      'ID-OP-DELEGATION-ISSUE',
      'ID-OP-DELEGATION-REVOKE',
    ]);
    expect(
      participantOperations
        .filter((operation) => extensionOperations.includes(operation.id))
        .map((operation) => operation.id),
    ).toEqual(extensionOperations);
    expect(Object.values(participantStates).flat()).toHaveLength(26);
    expect(participantEvents).toHaveLength(3);
  });

  it('requires step-up and maker-checker for participant mutations', () => {
    for (const operation of participantOperations) {
      expect(operation.webauthnStepUpRequired).toBe(true);
      expect(operation.makerCheckerRequired).toBe(true);
    }
  });
});
