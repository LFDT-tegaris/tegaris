import { describe, expect, it } from 'vitest';

import { createPrivacyExplorerExecutionOracle } from '../../../services/control-api/src/privacy-explorer/execution-oracle.js';
import { buildB4Boundary, buildB4Candidate } from '../../privacy/i07-gate2-b4-test-support.js';

describe('I07 Gate 2 B4 in-memory owner integration', () => {
  it('atomically joins a real B2 boundary, B3 candidate, release, completion, and evidence', () => {
    const boundary = buildB4Boundary();
    const oracle = createPrivacyExplorerExecutionOracle();
    const handle = oracle.create(boundary);
    const apply = (
      eventId: Parameters<typeof oracle.apply>[2],
      candidate?: ReturnType<typeof buildB4Candidate>,
    ) => {
      const snapshot = oracle.inspect(handle);
      return oracle.apply(
        handle,
        snapshot.revision,
        eventId,
        candidate ? { candidate } : undefined,
      );
    };
    for (const eventId of [
      'BIND_LOCAL_CONTEXT',
      'PREAUTHORIZE',
      'NARROW_INTENT',
      'CREATE_REQUEST',
      'START_READ',
      'CAPTURE_BYTES',
      'VALIDATE_PROJECTION',
      'REDACT_PROJECTION',
    ] as const)
      apply(eventId);
    apply('SELECT_COMPLETE', buildB4Candidate(boundary));
    apply('DISPOSE_RAW');
    const release = apply('RELEASE');
    expect(release.released).toMatchObject({ outcome: 'COMPLETE', truthState: 'TRUE' });
    const seal = apply('MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
    expect(seal.snapshot).toMatchObject({
      state: 'EVIDENCE_SEALED',
      rawState: 'DISPOSED',
      delivery: 'RELEASED',
    });
    expect(seal.evidence?.occurrenceId).toBe(boundary.request.occurrence.requestId);
  });

  it('closes a cancellation race without release or evidence leakage', () => {
    const boundary = buildB4Boundary();
    const oracle = createPrivacyExplorerExecutionOracle();
    const handle = oracle.create(boundary);
    const apply = (eventId: Parameters<typeof oracle.apply>[2]) => {
      const snapshot = oracle.inspect(handle);
      return oracle.apply(handle, snapshot.revision, eventId);
    };
    for (const eventId of [
      'BIND_LOCAL_CONTEXT',
      'PREAUTHORIZE',
      'NARROW_INTENT',
      'CREATE_REQUEST',
      'START_READ',
      'CANCEL_DURING_READ',
      'CAPTURE_LATE_BYTES',
      'DISPOSE_RAW',
      'CLOSE_CANCELLED',
    ] as const)
      apply(eventId);
    const terminal = oracle.inspect(handle);
    expect(terminal).toMatchObject({
      state: 'CANCELLED_CLOSED',
      rawState: 'DISPOSED',
      delivery: 'SUPPRESSED',
      outcome: 'CANCELLED_AFTER_RAW',
    });
    expect(() => apply('RELEASE')).toThrow('undeclared execution event');
    const sealed = apply('MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
    expect(sealed.evidence).toMatchObject({
      rawState: 'DISPOSED',
      outcome: 'CANCELLED_AFTER_RAW',
    });
  });
});
